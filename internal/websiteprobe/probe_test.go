package websiteprobe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestTargetIsAnOriginNotAFetchURL(t *testing.T) {
	for s, want := range map[string]Target{
		"website.example.org":             {"website.example.org", 443},
		"https://website.example.org/":    {"website.example.org", 443},
		"https://WEBSITE.example.org:443": {"website.example.org", 443},
		"intranet.lab.az:8443":            {"intranet.lab.az", 8443},
		"https://intranet:8443/":          {"intranet", 8443},
		"nas.home.arpa":                   {"nas.home.arpa", 443},
		"printer.local:631":               {"printer.local", 631},
		"10.0.0.5":                        {"10.0.0.5", 443},
		"https://192.168.1.20:9443":       {"192.168.1.20", 9443},
		"fd00::1":                         {"fd00::1", 443},
		"[fd00::1]:8443":                  {"fd00::1", 8443},
		"https://[2001:4860:4860::8888]":  {"2001:4860:4860::8888", 443},
	} {
		if got, err := ParseTarget(s); err != nil || got != want {
			t.Fatalf("valid target %q: %+v %v", s, got, err)
		}
	}
	for _, s := range []string{"", " website.example.org", "http://website.example.org", "https://website.example.org/a", "https://website.example.org/?", "https://website.example.org/#", "https://website.example.org/#x", "https://website.example.org:", "https://website.example.org:0", "https://website.example.org:65536", "https://website.example.org:08443", "https://website.example.org:+1", "https://user:secret@website.example.org", "https://website.example.org\\@localhost", "localhost", "a.localhost:8443", "website.example.org.", "website.example.org%00.evil.com", "a..org", "a.-b.org", strings.Repeat("a", 64) + ".org", "10.1", "3232235777", "010.0.0.1", "[fe80::1%25eth0]", "::ffff:10.0.0.1", "[::ffff:10.0.0.1]:443", "[website.example.org]", "[::1.2.3.4]", "ftp://website.example.org", "website_example.org"} {
		if got, err := ParseTarget(s); err == nil {
			t.Fatalf("unsafe target accepted: %q as %+v", s, got)
		}
	}
	for _, tc := range []struct {
		target Target
		text   string
	}{{Target{"website.example.org", 443}, "website.example.org"}, {Target{"10.0.0.5", 8443}, "10.0.0.5:8443"}, {Target{"fd00::1", 8443}, "[fd00::1]:8443"}} {
		if tc.target.String() != tc.text {
			t.Fatalf("%+v reads as %q", tc.target, tc.target.String())
		}
	}
}

func TestOwnMachineLinkLocalAndReservedAddressesAreRefused(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "127.255.0.9", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::", "169.254.169.254", "100.100.100.200", "fd00:ec2::254", "192.0.0.1", "192.0.2.1", "198.51.100.7", "203.0.113.9", "224.0.0.1", "239.1.1.1", "255.255.255.255", "240.0.0.1", "fe80::1", "ff02::1", "2001:db8::1", "2001::1", "2002:7f00:1::", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "3fff::1", "fec0::1"} {
		if allowedAddress(netip.MustParseAddr(s)) {
			t.Fatal("unsafe destination allowed:", s)
		}
	}
	if allowedAddress(netip.MustParseAddr("fe80::1%eth0")) || allowedAddress(netip.Addr{}) {
		t.Fatal("zoned or empty address allowed")
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "10.0.0.1", "172.16.5.4", "172.31.255.254", "192.168.1.1", "100.64.0.1", "100.100.100.100", "198.18.0.1", "fd00::1", "fd12:3456::7", "2606:4700:4700::1111", "::ffff:10.0.0.1", "::ffff:8.8.8.8"} {
		if !allowedAddress(netip.MustParseAddr(s)) {
			t.Fatal("public or private server refused:", s)
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
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "website.example.org"}, DNSNames: []string{"website.example.org"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.5")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, leafPub, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, roots
}

// server answers each dial with a fresh in-memory connection. behave runs the
// server side of attempt n (zero-based) and reports what it saw.
type server struct {
	t      *testing.T
	mu     sync.Mutex
	dialed []string
	behave func(n int, conn net.Conn) error
	done   chan error
}

func newServer(t *testing.T, behave func(n int, conn net.Conn) error) *server {
	return &server{t: t, behave: behave, done: make(chan error, 8)}
}

func (s *server) dial(_ context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		s.t.Fatal("not TCP")
	}
	s.mu.Lock()
	n := len(s.dialed)
	s.dialed = append(s.dialed, address)
	s.mu.Unlock()
	client, peer := net.Pipe()
	go func() { defer peer.Close(); s.done <- s.behave(n, peer) }()
	s.t.Cleanup(func() { _ = client.Close() })
	return client, nil
}

// handshake serves certificate with config and checks the client sends no
// application data.
func handshake(conn net.Conn, config *tls.Config) error {
	s := tls.Server(conn, config)
	if err := s.Handshake(); err != nil {
		return err
	}
	b := make([]byte, 1)
	if n, _ := s.Read(b); n != 0 {
		return errors.New("application data sent")
	}
	return nil
}

func lookupOnly(t *testing.T, name string, ips ...string) func(context.Context, string, string) ([]netip.Addr, error) {
	return func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != name {
			t.Fatalf("wrong lookup %s %s", network, host)
		}
		var out []netip.Addr
		for _, ip := range ips {
			out = append(out, netip.MustParseAddr(ip))
		}
		return out, nil
	}
}

func TestRealSyntheticTLSIsPinnedSNIOnlyAndSeparatelyVerified(t *testing.T) {
	certificate, roots := tlsFixture(t)
	for _, tc := range []struct {
		name, target, ip, dialed, sni string
		trusted                       bool
	}{
		{"public name", "website.example.org", "1.1.1.1", "1.1.1.1:443", "website.example.org", true},
		{"untrusted", "website.example.org", "1.1.1.1", "1.1.1.1:443", "website.example.org", false},
		{"internal name and port", "website.example.org:8443", "10.0.0.5", "10.0.0.5:8443", "website.example.org", true},
		{"internal address", "10.0.0.5:8443", "", "10.0.0.5:8443", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(t, func(_ int, conn net.Conn) error {
				return handshake(conn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					if hello.ServerName != tc.sni {
						return nil, errors.New("wrong SNI")
					}
					return nil, nil
				}})
			})
			lookups := 0
			pool := roots
			if !tc.trusted {
				_, pool = tlsFixture(t)
			}
			target, err := ParseTarget(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			r, err := probe(context.Background(), target, nil, func() bool { return true }, dependencies{
				lookup: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
					lookups++
					return lookupOnly(t, "website.example.org", tc.ip)(ctx, network, host)
				},
				dial:  srv.dial,
				roots: func() (*x509.CertPool, error) { return pool, nil }, now: time.Now,
			})
			wantLookups := 1
			if tc.ip == "" {
				wantLookups = 0
			}
			if err != nil || r.Trusted != tc.trusted || !r.HostnameMatches || lookups != wantLookups || len(srv.dialed) != 1 || srv.dialed[0] != tc.dialed || r.Address+":"+map[bool]string{true: "443", false: "8443"}[target.Port == 443] != tc.dialed || r.Port != target.Port {
				t.Fatalf("observation %+v %v %v", r, err, srv.dialed)
			}
			if err := <-srv.done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRefusalsHaveNoDialOrPartialReport(t *testing.T) {
	_, roots := tlsFixture(t)
	for _, mode := range []string{"mixed", "loopback", "metadata", "address-loopback", "too-many", "revoked-before", "revoked-after-dns", "roots", "lookup-error", "not-found", "empty", "dial-error"} {
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
					switch mode {
					case "lookup-error":
						return nil, errors.New("sensitive sentinel")
					case "not-found":
						return nil, &net.DNSError{Err: "sensitive sentinel", IsNotFound: true}
					case "empty":
						return nil, nil
					}
					ips := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
					switch mode {
					case "mixed":
						ips = append(ips, netip.MustParseAddr("127.0.0.1"))
					case "loopback":
						ips[0] = netip.MustParseAddr("::1")
					case "metadata":
						ips[0] = netip.MustParseAddr("169.254.169.254")
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
			target := Target{"website.example.org", 443}
			if mode == "address-loopback" {
				target = Target{"127.0.0.1", 8443}
			}
			r, err := probe(context.Background(), target, nil, func() bool { return allowed }, deps)
			want := 0
			if mode == "dial-error" {
				want = 1
			}
			if err == nil || r.Schema != "" || calls != want || strings.Contains(err.Error(), "sentinel") {
				t.Fatalf("unsafe refusal: %+v %v %d", r, err, calls)
			}
			wantErr := map[string]error{"mixed": ErrBlocked, "loopback": ErrBlocked, "metadata": ErrBlocked, "address-loopback": ErrBlocked, "too-many": ErrBlocked, "roots": ErrTrustStore, "lookup-error": ErrDNS, "not-found": ErrNotFound, "empty": ErrNotFound}[mode]
			if wantErr != nil && !errors.Is(err, wantErr) {
				t.Fatalf("%s: got %v, want %v", mode, err, wantErr)
			}
		})
	}
	if _, err := probe(context.Background(), Target{"Website.example.org", 443}, nil, func() bool { return true }, dependencies{}); !errors.Is(err, ErrTarget) {
		t.Fatal("a target that is not canonical reached the network")
	}
	if runtime.GOOS != "linux" {
		if _, err := Probe(context.Background(), Target{"website.example.org", 443}, nil, func() bool { t.Fatal("unsupported platform called permit"); return true }); err != ErrUnavailable {
			t.Fatal("native network allowed")
		}
	}
}

func TestFailuresSayWhatHappened(t *testing.T) {
	certificate, roots := tlsFixture(t)
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	for _, tc := range []struct {
		name   string
		ips    []string
		dial   func(n int) error
		behave func(conn net.Conn) error
		want   error
		dials  int
		last   string
	}{
		{"nothing listens", []string{"10.0.0.1"}, func(int) error { return refused }, nil, ErrRefused, 1, "10.0.0.1"},
		{"silent, then IPv6 also silent", []string{"fd00::1", "10.0.0.1"}, func(int) error { return context.DeadlineExceeded }, nil, ErrTimeout, 2, "fd00::1"},
		{"not TLS", []string{"10.0.0.1"}, nil, func(conn net.Conn) error {
			header := make([]byte, 5)
			_, _ = io.ReadFull(conn, header)
			_, _ = io.ReadFull(conn, make([]byte, int(header[3])<<8|int(header[4])))
			_, err := conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return err
		}, ErrNotTLS, 1, "10.0.0.1"},
		{"refuses TLS", []string{"10.0.0.1"}, nil, func(conn net.Conn) error {
			_ = tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, errors.New("no") }}).Handshake()
			return nil
		}, ErrHandshake, 1, "10.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dialed []string
			srv := newServer(t, func(_ int, conn net.Conn) error { return tc.behave(conn) })
			_, err := probe(context.Background(), Target{"website.example.org", 8443}, nil, func() bool { return true }, dependencies{
				lookup: lookupOnly(t, "website.example.org", tc.ips...),
				dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					dialed = append(dialed, address)
					if tc.dial != nil {
						return nil, tc.dial(len(dialed))
					}
					return srv.dial(ctx, network, address)
				},
				roots: func() (*x509.CertPool, error) { return roots, nil }, now: time.Now,
			})
			var failure *Failure
			if !errors.Is(err, tc.want) || !errors.As(err, &failure) || failure.Address != tc.last || len(dialed) != tc.dials {
				t.Fatalf("got %v (%+v), dialed %v", err, failure, dialed)
			}
			if dialed[0] != "10.0.0.1:8443" {
				t.Fatal("IPv4 was not tried first:", dialed)
			}
		})
	}
}

// dropBigGreeting closes the connection when the client's first TLS record
// is as large as a post-quantum greeting, like some firewalls do, and serves
// a smaller one normally.
func dropBigGreeting(config *tls.Config) func(int, net.Conn) error {
	return func(_ int, conn net.Conn) error {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return err
		}
		body := make([]byte, int(header[3])<<8|int(header[4]))
		if _, err := io.ReadFull(conn, body); err != nil {
			return err
		}
		if len(body) > 1000 {
			return conn.Close()
		}
		return handshake(&replayConn{Conn: conn, first: append(header, body...)}, config)
	}
}

type replayConn struct {
	net.Conn
	first []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.first) > 0 {
		n := copy(p, c.first)
		c.first = c.first[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func TestClassicRetryWhenTheGreetingIsDropped(t *testing.T) {
	certificate, roots := tlsFixture(t)
	srv := newServer(t, dropBigGreeting(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}))
	r, err := probe(context.Background(), Target{"website.example.org", 443}, nil, func() bool { return true }, dependencies{
		lookup: lookupOnly(t, "website.example.org", "10.0.0.5"), dial: srv.dial,
		roots: func() (*x509.CertPool, error) { return roots, nil }, now: time.Now,
	})
	if err != nil || !r.Trusted || len(srv.dialed) != 2 || srv.dialed[1] != "10.0.0.5:443" || r.Findings[len(r.Findings)-1].Code != "classic-key-exchange" || r.State != "verified" {
		t.Fatalf("no classic retry: %+v %v %v", r, err, srv.dialed)
	}
	// A server that drops every greeting gets one classic attempt, not one per
	// address: the server answered, so the other address would not say more.
	closer := newServer(t, func(_ int, conn net.Conn) error { _, _ = io.ReadFull(conn, make([]byte, 5)); return conn.Close() })
	_, err = probe(context.Background(), Target{"website.example.org", 443}, nil, func() bool { return true }, dependencies{
		lookup: lookupOnly(t, "website.example.org", "fd00::5", "10.0.0.5"), dial: closer.dial,
		roots: func() (*x509.CertPool, error) { return roots, nil }, now: time.Now,
	})
	if !errors.Is(err, ErrHandshake) || len(closer.dialed) != 2 || closer.dialed[1] != "10.0.0.5:443" {
		t.Fatalf("retries not bounded: %v %v", err, closer.dialed)
	}
	// The classic attempt times out, so the IPv6 address is tried; it gets no
	// second classic attempt. Three connections at most.
	var dialed []string
	_, err = probe(context.Background(), Target{"website.example.org", 443}, nil, func() bool { return true }, dependencies{
		lookup: lookupOnly(t, "website.example.org", "fd00::5", "10.0.0.5"),
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			if len(dialed) == 2 {
				return nil, context.DeadlineExceeded
			}
			return closer.dial(ctx, network, address)
		},
		roots: func() (*x509.CertPool, error) { return roots, nil }, now: time.Now,
	})
	if !errors.Is(err, ErrHandshake) || len(dialed) != 3 || dialed[2] != "[fd00::5]:443" {
		t.Fatalf("more than three connections: %v %v", err, dialed)
	}
}

func TestIncompleteHandshakeStillShowsCertificatesAndRepeatsAreNamed(t *testing.T) {
	certificate, roots := tlsFixture(t)
	repeated := certificate
	repeated.Certificate = [][]byte{certificate.Certificate[0], certificate.Certificate[0]}
	for _, tc := range []struct {
		name   string
		config *tls.Config
		code   string
		state  string
	}{
		{"client certificate required", &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAnyClientCert}, "handshake-incomplete", "verified"},
		{"certificate sent twice", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{repeated}}, "repeated", "attention"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(t, func(_ int, conn net.Conn) error { _ = tls.Server(conn, tc.config).Handshake(); return nil })
			r, err := probe(context.Background(), Target{"website.example.org", 443}, nil, func() bool { return true }, dependencies{
				lookup: lookupOnly(t, "website.example.org", "10.0.0.5"), dial: srv.dial,
				roots: func() (*x509.CertPool, error) { return roots, nil }, now: time.Now,
			})
			if err != nil || !r.Trusted || len(r.Presented) != 1 || r.Findings[len(r.Findings)-1].Code != tc.code || r.State != tc.state || len(srv.dialed) != 1 {
				t.Fatalf("certificates not shown: %+v %v", r, err)
			}
		})
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
			r, err := probe(ctx, Target{"website.example.org", 443}, nil, func() bool { return allowed }, dependencies{
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
			allowed := true
			dials := 0
			var wg sync.WaitGroup
			defer wg.Wait()
			if mode == "cancel-handshake" {
				// A peer that never responds must not keep a canceled observation alive.
				timer := time.AfterFunc(30*time.Millisecond, cancel)
				defer timer.Stop()
			}
			r, err := probe(ctx, Target{"website.example.org", 443}, nil, func() bool { return allowed }, dependencies{
				lookup: func(context.Context, string, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
				},
				dial: func(context.Context, string, string) (net.Conn, error) {
					dials++
					client, server := net.Pipe()
					t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
					if mode == "revoke-after-handshake" {
						wg.Add(1)
						go func() {
							defer wg.Done()
							s := tls.Server(server, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
							_ = s.HandshakeContext(ctx)
							_ = server.Close()
						}()
					}
					return client, nil
				},
				roots: func() (*x509.CertPool, error) { return roots, nil },
				now:   func() time.Time { allowed = false; return time.Now() },
			})
			if err == nil || r.Schema != "" || dials > 2 {
				t.Fatalf("canceled or revoked handshake produced a report: %v %d", err, dials)
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
	for _, s := range []string{"website.example.org", "https://127.0.0.1", "https://website.example.org/?a=b", "[fd00::1]:8443", "intranet:8443", "10.0.0.5:443"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		target, err := ParseTarget(s)
		if err != nil {
			return
		}
		if target.Port < 1 || target.Port > 65535 || target.Host == "" || strings.ContainsAny(target.Host, "/@?#[]% \\") || bytes.ContainsAny([]byte(target.Host), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Fatalf("unsafe target %+v from %q", target, s)
		}
		for _, again := range []string{target.String(), "https://" + target.String() + "/"} {
			if normalized, e := ParseTarget(again); e != nil || normalized != target {
				t.Fatalf("non-canonical target %+v from %q: %q gives %+v %v", target, s, again, normalized, e)
			}
		}
	})
}
