package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/denyfirst/rootwell/internal/servecert"
	"github.com/denyfirst/rootwell/internal/servingstore"
)

func hostRequest(method, host, path, origin, body string) *http.Request {
	r := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	r.Host = host
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Rootwell-Request", "1")
	}
	return r
}

func TestOnlyHTTPSToTheConfiguredNamesIsServed(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		e.g.ServeHTTP(w, r)
		return w
	}
	plain := httptest.NewRequest("GET", "http://"+localHost+"/login", nil)
	if w := serve(plain); w.Code != http.StatusBadRequest {
		t.Fatalf("plain HTTP: %d", w.Code)
	}
	hsts := map[string]bool{"localhost:4180": false, "127.0.0.1:4180": false, "[::1]:4180": false,
		"rootwell.lan:4180": true, "192.0.2.10:4180": true}
	for host, lan := range hsts {
		w := serve(hostRequest("GET", host, "/login", "", ""))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", host, w.Code)
		}
		if got := w.Header().Get("Strict-Transport-Security"); (got != "") != lan || (lan && got != "max-age=31536000") {
			t.Fatalf("%s HSTS %q", host, got)
		}
	}
	for _, host := range []string{"rootwell.lan:443", "rootwell.lan", "evil.example:4180", "192.0.2.11:4180", "LOCALHOST:4180"} {
		if w := serve(hostRequest("GET", host, "/login", "", "")); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", host, w.Code)
		}
	}
	// The Origin must be this very name, over HTTPS.
	body := `{"name":"ada","password":"not the password at all"}`
	for origin, want := range map[string]int{
		"https://rootwell.lan:4180": http.StatusUnauthorized,
		"https://localhost:4180":    http.StatusForbidden,
		"http://rootwell.lan:4180":  http.StatusForbidden,
		"https://rootwell.lan":      http.StatusForbidden,
	} {
		if w := serve(hostRequest("POST", "rootwell.lan:4180", "/api/session", origin, body)); w.Code != want {
			t.Fatalf("origin %s: %d, want %d", origin, w.Code, want)
		}
	}
	// The authority's certificate is public, and is the one the server uses.
	w := serve(hostRequest("GET", "localhost:4180", "/rootwell-ca.pem", "", ""))
	block, _ := pem.Decode(w.Body.Bytes())
	if w.Code != http.StatusOK || block == nil || !bytes.Equal(block.Bytes, e.serving.Authority.Raw) ||
		!strings.Contains(w.Header().Get("Content-Disposition"), "rootwell-ca.pem") {
		t.Fatalf("authority download: %d", w.Code)
	}
}

func TestTheServerSpeaksTLS13OnlyAndTheAuthorityVerifiesIt(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	var current atomic.Pointer[tls.Certificate]
	current.Store(e.serving.Certificate)
	// As serve does it: a TLS listener with only the gate's config.
	plainListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: e.g, TLSConfig: tlsConfig(&current)}
	go func() { _ = server.ServeTLS(plainListener, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	roots := x509.NewCertPool()
	roots.AddCert(e.serving.Authority)
	address := plainListener.Addr().String()
	for _, name := range []string{"localhost", "rootwell.lan"} {
		conn, err := tls.Dial("tcp", address, &tls.Config{RootCAs: roots, ServerName: name})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		state := conn.ConnectionState()
		_ = conn.Close()
		if state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 {
			t.Fatalf("%s: version %x, key exchange %v", name, state.Version, state.CurveID)
		}
	}
	if conn, err := tls.Dial("tcp", address, &tls.Config{RootCAs: roots, ServerName: "localhost", MaxVersion: tls.VersionTLS12}); err == nil {
		_ = conn.Close()
		t.Fatal("a TLS 1.2 client was served")
	}
	if conn, err := tls.Dial("tcp", address, &tls.Config{RootCAs: roots, ServerName: "evil.example"}); err == nil {
		_ = conn.Close()
		t.Fatal("the certificate verified for a name it does not cover")
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}}
	response, err := client.Get("https://localhost:4180/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("a real HTTPS request: %d", response.StatusCode)
	}
	// A renewed certificate is served from the next connection on, also to a
	// client that names no server, as one that connects by address does.
	renewed, err := servingstore.SetNames(e.v, []string{"rootwell.lan"}, e.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	current.Store(renewed.Certificate)
	conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- reads which certificate is served.
	if err != nil {
		t.Fatal(err)
	}
	served := conn.ConnectionState().PeerCertificates[0]
	_ = conn.Close()
	if !bytes.Equal(served.Raw, renewed.Certificate.Leaf.Raw) {
		t.Fatal("the server kept the old certificate")
	}
}

func TestListenTakesOnlyCoveredHostAddresses(t *testing.T) {
	names, err := servecert.ParseNames([]string{"rootwell.lan", "192.0.2.10", "2001:db8::10"})
	if err != nil {
		t.Fatal(err)
	}
	s := servingstore.Serving{Names: names}
	if got, err := listenAddresses([]string{"192.0.2.10", "2001:db8::10"}, s); err != nil || len(got) != 2 {
		t.Fatalf("covered addresses: %v %v", got, err)
	}
	for _, bad := range []string{"0.0.0.0", "::", "127.0.0.1", "::1", "192.0.2.11", "rootwell.lan", "224.0.0.1", ""} {
		if _, err := listenAddresses([]string{bad}, s); err == nil {
			t.Fatalf("--listen %q was accepted", bad)
		}
	}
	// Every address, loopback and multicast stay refused even if a damaged
	// record listed them as covered.
	damaged := servingstore.Serving{Names: servecert.Names{IPs: []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified(),
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("224.0.0.1")}}}
	for _, bad := range []string{"0.0.0.0", "::", "127.0.0.1", "224.0.0.1"} {
		if _, err := listenAddresses([]string{bad}, damaged); err == nil {
			t.Fatalf("--listen %q was accepted from a damaged record", bad)
		}
	}
	for _, args := range [][]string{{"--listen"}, {"--port", "1"}, {"192.0.2.10"}, {"--listen", "a", "b"}} {
		if _, ok := listenFlags(args); ok {
			t.Fatalf("flags %q were accepted", args)
		}
	}
	if got, ok := listenFlags([]string{"--listen", "192.0.2.10", "--listen", "2001:db8::10"}); !ok || len(got) != 2 {
		t.Fatalf("two --listen flags: %v", got)
	}
}
