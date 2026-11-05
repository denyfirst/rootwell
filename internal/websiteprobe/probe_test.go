package websiteprobe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTargetIsAnOriginNotAFetchURL(t *testing.T) {
	for _, s := range []string{"website.example.org", "https://website.example.org/", "https://WEBSITE.example.org:443"} {
		if host, err := ParseTarget(s); err != nil || host != "website.example.org" {
			t.Fatalf("valid target %q: %q %v", s, host, err)
		}
	}
	for _, s := range []string{"", " website.example.org", "http://website.example.org", "https://website.example.org/a", "https://website.example.org/?", "https://website.example.org/#", "https://website.example.org/#x", "https://website.example.org:444", "https://website.example.org:", "https://user:secret@website.example.org", "127.0.0.1", "[::1]", "https://website.example.org\\@localhost", "localhost", "a.local", "a.home.arpa", "a.onion", "a.test", "a.invalid", "a.example", "website.example.org.", "website.example.org%00.evil.com", "a..org", "a.-b.org", strings.Repeat("a", 64) + ".org"} {
		if _, err := ParseTarget(s); err == nil {
			t.Fatalf("unsafe target accepted: %q", s)
		}
	}
}

func TestSpecialUseAndMappedAddressesAreRefused(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "192.168.1.1", "192.0.0.1", "192.0.2.1", "198.18.0.1", "224.0.0.1", "255.255.255.255", "fc00::1", "fe80::1", "2001:db8::1", "2002:7f00:1::", "64:ff9b::7f00:1", "3fff::1"} {
		if publicAddress(netip.MustParseAddr(s)) {
			t.Fatal("unsafe destination", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !publicAddress(netip.MustParseAddr(s)) {
			t.Fatal("public address refused", s)
		}
	}
}

func tlsFixture(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic TLS Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "website.example.org"}, DNSNames: []string{"website.example.org"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, leafPub, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, roots
}

func TestRealSyntheticTLSIsPinnedSNIOnlyAndSeparatelyVerified(t *testing.T) {
	certificate, roots := tlsFixture(t)
	for _, trusted := range []bool{true, false} {
		t.Run(map[bool]string{true: "trusted", false: "untrusted"}[trusted], func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				s := tls.Server(server, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					if hello.ServerName != "website.example.org" {
						return nil, errors.New("wrong SNI")
					}
					return nil, nil
				}})
				if err := s.Handshake(); err != nil {
					done <- err
					return
				}
				b := make([]byte, 1)
				n, _ := s.Read(b)
				if n != 0 {
					done <- errors.New("application data sent")
					return
				}
				done <- nil
			}()
			lookups, dials := 0, 0
			pool := roots
			if !trusted {
				pool = x509.NewCertPool()
				_, other := tlsFixture(t)
				pool = other
			}
			r, err := probe(context.Background(), "website.example.org", func() bool { return true }, dependencies{
				lookup: func(_ context.Context, network, host string) ([]netip.Addr, error) {
					lookups++
					if network != "ip" || host != "website.example.org" {
						t.Fatal("wrong lookup")
					}
					return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
				},
				dial: func(_ context.Context, network, address string) (net.Conn, error) {
					dials++
					if network != "tcp" || address != "1.1.1.1:443" {
						t.Fatal("DNS was not pinned")
					}
					return client, nil
				},
				roots: func() (*x509.CertPool, error) { return pool, nil }, now: time.Now,
			})
			if err != nil || r.Trusted != trusted || lookups != 1 || dials != 1 || r.Address != "1.1.1.1" {
				t.Fatalf("observation %+v %v", r, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRefusalsHaveNoDialOrPartialReport(t *testing.T) {
	_, roots := tlsFixture(t)
	for _, mode := range []string{"mixed", "private", "too-many", "revoked-before", "revoked-after-dns", "roots", "lookup-error", "dial-error"} {
		t.Run(mode, func(t *testing.T) {
			allowed := mode != "revoked-before"
			calls := 0
			deps := dependencies{roots: func() (*x509.CertPool, error) {
				if mode == "roots" {
					return nil, errors.New("sensitive sentinel")
				}
				return roots, nil
			}, now: time.Now,
				lookup: func(context.Context, string, string) ([]netip.Addr, error) {
					if mode == "lookup-error" {
						return nil, errors.New("sensitive sentinel")
					}
					ips := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
					switch mode {
					case "mixed":
						ips = append(ips, netip.MustParseAddr("127.0.0.1"))
					case "private":
						ips[0] = netip.MustParseAddr("10.0.0.1")
					case "too-many":
						for len(ips) < 17 {
							ips = append(ips, ips[0])
						}
					case "revoked-after-dns":
						allowed = false
					}
					return ips, nil
				},
				dial: func(context.Context, string, string) (net.Conn, error) {
					calls++
					return nil, errors.New("sensitive sentinel")
				}}
			r, err := probe(context.Background(), "website.example.org", func() bool { return allowed }, deps)
			want := 0
			if mode == "dial-error" {
				want = 1
			}
			if err == nil || r.Schema != "" || calls != want || strings.Contains(err.Error(), "sentinel") {
				t.Fatalf("unsafe refusal: %+v %v %d", r, err, calls)
			}
		})
	}
	if runtime.GOOS != "linux" {
		if _, err := Probe(context.Background(), "website.example.org", func() bool { t.Fatal("unsupported platform called permit"); return true }); err != ErrUnavailable {
			t.Fatal("native network allowed")
		}
	}
}

func TestCancellationAndRevocationAfterDialCloseWithoutHandshake(t *testing.T) {
	_, roots := tlsFixture(t)
	for _, mode := range []string{"cancel", "revoke", "nil-connection"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			allowed := true
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			r, err := probe(ctx, "website.example.org", func() bool { return allowed }, dependencies{
				roots: func() (*x509.CertPool, error) { return roots, nil }, now: time.Now,
				lookup: func(context.Context, string, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
				},
				dial: func(context.Context, string, string) (net.Conn, error) {
					switch mode {
					case "cancel":
						cancel()
					case "revoke":
						allowed = false
					case "nil-connection":
						return nil, nil
					}
					return client, nil
				},
			})
			if err == nil || r.Schema != "" {
				t.Fatal("revoked operation published")
			}
			if mode != "nil-connection" {
				b := make([]byte, 1)
				if n, _ := server.Read(b); n != 0 {
					t.Fatal("handshake started after authorization loss")
				}
			}
		})
	}
}

func TestHandshakeCancellationAndPostHandshakeRevocationPublishNothing(t *testing.T) {
	certificate, roots := tlsFixture(t)
	for _, mode := range []string{"cancel-handshake", "revoke-after-handshake"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			allowed := true
			if mode == "revoke-after-handshake" {
				done := make(chan struct{})
				go func() {
					defer close(done)
					s := tls.Server(server, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
					_ = s.HandshakeContext(ctx)
				}()
				defer func() { _ = client.Close(); <-done }()
			} else {
				// A peer that never responds must not keep a canceled observation alive.
				timer := time.AfterFunc(30*time.Millisecond, cancel)
				defer timer.Stop()
			}
			r, err := probe(ctx, "website.example.org", func() bool { return allowed }, dependencies{
				lookup: func(context.Context, string, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
				},
				dial:  func(context.Context, string, string) (net.Conn, error) { return client, nil },
				roots: func() (*x509.CertPool, error) { return roots, nil },
				now:   func() time.Time { allowed = false; return time.Now() },
			})
			if err == nil || r.Schema != "" {
				t.Fatal("canceled or revoked handshake produced a report")
			}
		})
	}
}

func TestBoundedConnectionStopsUnboundedPeerInputAndWrites(t *testing.T) {
	conn := &byteConn{}
	bounded := &boundedConn{Conn: conn, remainingRead: 3, remainingWrite: 2}
	buf := make([]byte, 4)
	if n, _ := bounded.Read(buf); n != 3 {
		t.Fatal("read limit not applied")
	}
	if n, err := bounded.Read(buf); n != 0 || err == nil {
		t.Fatal("read continued after limit")
	}
	if n, err := bounded.Write([]byte{1, 2, 3}); n != 0 || err == nil || conn.writes != 0 {
		t.Fatal("oversized write reached socket")
	}
}

type byteConn struct {
	net.Conn
	writes int
}

func (c *byteConn) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 1
	}
	return len(p), nil
}
func (c *byteConn) Write(p []byte) (int, error) { c.writes++; return len(p), nil }

func FuzzTarget(f *testing.F) {
	for _, s := range []string{"website.example.org", "https://127.0.0.1", "https://website.example.org/?a=b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		host, err := ParseTarget(s)
		if err == nil {
			if normalized, e := ParseTarget("https://" + host + ":443/"); e != nil || normalized != host {
				t.Fatal("non-canonical target")
			}
		}
	})
}
