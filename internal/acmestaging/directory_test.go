package acmestaging

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeplan"
)

func directoryJSON() string {
	return `{"newNonce":"https://` + host + `/acme/new-nonce","newAccount":"https://` + host + `/acme/new-acct","newOrder":"https://` + host + `/acme/new-order","revokeCert":"https://` + host + `/acme/revoke-cert","keyChange":"https://` + host + `/acme/key-change","meta":{"termsOfService":"https://letsencrypt.org/documents/terms.pdf"},"random-extension":"ignored"}`
}

func fakeCA(t *testing.T, handler http.HandlerFunc) (dependencies, *atomic.Int32) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	clear(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	var lookups atomic.Int32
	return dependencies{
		lookup: func(_ context.Context, network, name string) ([]netip.Addr, error) {
			if network != "ip" || name != host {
				t.Error("unexpected DNS authority")
			}
			lookups.Add(1)
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "8.8.8.8:443" {
				t.Error("dial was not pinned to approved numeric address")
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, server.Listener.Addr().String())
		},
		tls: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
	}, &lookups
}

func TestDirectoryDiscoveryUsesOnePinnedTLSGETWithoutSecrets(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	var calls atomic.Int32
	deps, lookups := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.RequestURI() != "/directory" || r.Host != host || r.TLS.ServerName != host || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Encoding") != "" {
			t.Error("unexpected request metadata or leaked authority")
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Error("directory request sent data")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, directoryJSON())
	})
	result, err := discover(context.Background(), func() bool { return true }, deps)
	if err != nil || result.Schema != "rootwell.acme.directory.v1" || result.Directory != acmeplan.Directory || !result.NetworkUsed || result.CanIssue || result.AccountCreated || result.DomainsSent || result.Saved || calls.Load() != 1 || lookups.Load() != 1 {
		t.Fatalf("discovery failed or acquired capabilities: %v", err)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "termsOfService") || strings.Contains(string(encoded), "new-acct") {
		t.Fatal("CA metadata reflected")
	}
}

func TestDirectoryRefusesPrivateMixedDNSAndRevokedConsentBeforeDial(t *testing.T) {
	for _, addresses := range [][]netip.Addr{nil, {netip.MustParseAddr("127.0.0.1")}, {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}, make([]netip.Addr, 17)} {
		deps := dependencies{lookup: func(context.Context, string, string) ([]netip.Addr, error) { return addresses, nil }, dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("unsafe DNS result dialed")
			return nil, errors.New("sentinel")
		}}
		if result, err := discover(context.Background(), func() bool { return true }, deps); err == nil || result.NetworkUsed {
			t.Fatal("unsafe DNS accepted")
		}
	}
	permitted := true
	deps := dependencies{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
		permitted = false
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}, dial: func(context.Context, string, string) (net.Conn, error) {
		t.Error("revoked request dialed")
		return nil, nil
	}}
	if _, err := discover(context.Background(), func() bool { return permitted }, deps); err == nil {
		t.Fatal("revocation ignored")
	}
	deps.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("unapproved request resolved DNS")
		return nil, nil
	}
	if _, err := discover(context.Background(), nil, deps); err == nil {
		t.Fatal("missing consent accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := discover(ctx, func() bool { return true }, deps); err == nil {
		t.Fatal("cancelled request accepted")
	}
}

func TestDirectorySpecialAddressesAreDenied(t *testing.T) {
	for _, value := range []string{"0.1.1.1", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.31.1.1", "192.0.0.9", "192.0.2.1", "192.88.99.1", "192.168.0.1", "198.18.1.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "::", "::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "fc00::1", "fe80::1%zone", "2001::1", "2001:db8::1", "2002:7f00:1::", "3fff::1", "ff02::1"} {
		if publicAddress(netip.MustParseAddr(value)) {
			t.Errorf("special address accepted: %s", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "::ffff:8.8.8.8", "2606:4700:4700::1111"} {
		if !publicAddress(netip.MustParseAddr(value)) {
			t.Errorf("public address refused: %s", value)
		}
	}
}

func TestDirectoryResponseRefusalsNeverRetryOrReflect(t *testing.T) {
	for _, mode := range []string{"redirect", "retry", "type", "encoding", "large", "chunked-large", "headers", "slow-body", "malformed", "untrusted", "wrong-hostname", "cancel", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			permitted := true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "slow-body" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
				defer stop()
			}
			deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "redirect":
					w.Header().Set("Location", "http://127.0.0.1/secret-sentinel")
					w.WriteHeader(302)
				case "retry":
					w.Header().Set("Retry-After", "1000")
					w.WriteHeader(503)
				case "type":
					w.Header().Set("Content-Type", "text/html")
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
				case "large":
					_, _ = io.WriteString(w, strings.Repeat("x", maxBody+1))
					return
				case "chunked-large":
					w.(http.Flusher).Flush()
					_, _ = io.WriteString(w, strings.Repeat("x", maxBody+1))
					return
				case "headers":
					w.Header().Set("X-Large", strings.Repeat("x", 16384))
				case "slow-body":
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				case "malformed":
					_, _ = io.WriteString(w, `{"newOrder":"secret-sentinel"}`)
					return
				case "cancel":
					cancel()
				}
				_, _ = io.WriteString(w, directoryJSON())
			})
			if mode == "untrusted" {
				deps.tls.RootCAs = x509.NewCertPool()
			}
			if mode == "wrong-hostname" {
				// Trust a valid TLS server whose certificate names example.com,
				// not the fixed ACME hostname. Numeric dialing must not bypass names.
				other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
				other.Config.ErrorLog = log.New(io.Discard, "", 0)
				t.Cleanup(other.Close)
				roots := x509.NewCertPool()
				roots.AddCert(other.Certificate())
				deps.tls.RootCAs = roots
				deps.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, other.Listener.Addr().String())
				}
			}
			// No shared variable is written by the server goroutine.
			if mode == "revoked" {
				prior := deps.dial
				deps.dial = func(ctx context.Context, n, a string) (net.Conn, error) {
					conn, err := prior(ctx, n, a)
					permitted = false
					return conn, err
				}
			}
			result, err := discover(ctx, func() bool { return permitted }, deps)
			if err == nil || result.NetworkUsed || strings.Contains(err.Error(), "secret-sentinel") || calls.Load() > 1 {
				t.Fatal("unsafe response accepted, retried or reflected")
			}
			if (mode == "revoked" || mode == "untrusted" || mode == "wrong-hostname") && calls.Load() != 0 {
				t.Fatal("HTTP sent after TLS/refused authorization")
			}
		})
	}
}

func TestDirectoryStrictBoundedParser(t *testing.T) {
	valid := directoryJSON()
	if !validDirectory([]byte(valid)) {
		t.Fatal("valid directory refused")
	}
	bad := []string{"null", "[]", valid + "{}", string([]byte{0xff}), strings.Repeat(" ", maxBody+1), strings.Replace(valid, `"newNonce":`, `"NewNonce":`, 1), strings.TrimSuffix(valid, "}") + `,"newOrder":"https://` + host + `/acme/order"}`, strings.Replace(valid, `"random-extension":"ignored"`, `"x":{"a":1,"a":2}`, 1), strings.Replace(valid, `"meta":{`, `"meta":null,"x":{`, 1)}
	bad = append(bad, strings.Replace(valid, `"random-extension":"ignored"`, `"x":`+strings.Repeat("[", 10)+"0"+strings.Repeat("]", 10), 1), strings.Replace(valid, `"random-extension":"ignored"`, `"x":[`+strings.Repeat("0,", 2049)+"0]", 1), strings.Replace(valid, `"newNonce":`, `"newNonce":null,"x":`, 1))
	for _, value := range []string{"http://" + host + "/acme/order", "https://evil.invalid/acme/order", "https://user@" + host + "/acme/order", "https://" + host + ":443/acme/order", "https://" + host + "/acme/../directory", "https://" + host + "/acme/%6frder", "https://" + host + "/acme/order?x=1", "https://" + host + "/acme/order#x", "https://" + host + "/acme/", "https://" + host + "/directory"} {
		bad = append(bad, strings.Replace(valid, "https://"+host+"/acme/new-order", value, 1))
	}
	for _, body := range bad {
		if validDirectory([]byte(body)) {
			t.Fatal("unsafe directory accepted")
		}
	}
}

type tripFunc func(*http.Request) (*http.Response, error)

func (f tripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDirectoryTransportCannotFollowEndpointsOrSendTwice(t *testing.T) {
	var calls int
	guard := &directoryTransport{allowed: func() bool { return true }, base: tripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(directoryJSON()))}, nil
	})}
	for _, target := range []string{"https://" + host + "/acme/new-order", "http://127.0.0.1/", acmeplan.Directory + "?secret=1"} {
		r, _ := http.NewRequest("GET", target, nil)
		if _, err := guard.RoundTrip(r); err == nil {
			t.Fatal("unreviewed endpoint allowed")
		}
	}
	r, _ := http.NewRequest("GET", acmeplan.Directory, nil)
	response, err := guard.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if _, err := guard.RoundTrip(r); err == nil || calls != 1 {
		t.Fatal("second GET allowed")
	}
}

func FuzzStagingDirectory(f *testing.F) {
	f.Add([]byte(directoryJSON()))
	f.Add([]byte(`{"newOrder":null}`))
	f.Add([]byte(`{"meta":{"x":1,"x":2}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxBody+1 {
			t.Skip()
		}
		if validDirectory(data) {
			var fields map[string]json.RawMessage
			if json.Unmarshal(data, &fields) != nil {
				t.Fatal("invalid JSON accepted")
			}
			for _, name := range []string{"newNonce", "newAccount", "newOrder", "revokeCert", "keyChange"} {
				var endpoint string
				if json.Unmarshal(fields[name], &endpoint) != nil || !safeEndpoint(endpoint) {
					t.Fatal("unsafe endpoint accepted")
				}
			}
		}
	})
}
