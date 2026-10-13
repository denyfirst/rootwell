//go:build linux

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func renewalNavigationCall(g *gate, cookie *http.Cookie, fields url.Values, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://"+localHost+"/automation/renew", strings.NewReader(fields.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func assertRenewalNavigation(t *testing.T, g *gate, cookie *http.Cookie, fp string, gen uint64) {
	t.Helper()
	fields := url.Values{"fingerprint": {fp}, "expected_generation": {strconv.FormatUint(gen, 10)}, "tool": {"renew"}}
	if w := renewalNavigationCall(g, nil, fields, "http://"+localHost); w.Code != 401 {
		t.Fatal("anonymous renewal selection")
	}
	if w := renewalNavigationCall(g, cookie, fields, "https://evil.invalid"); w.Code != 403 {
		t.Fatal("cross-origin renewal navigation")
	}
	w := renewalNavigationCall(g, cookie, fields, "http://"+localHost)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "rootwell.acme.renewal-selection.v1") || !strings.Contains(w.Body.String(), fp) || !strings.Contains(w.Body.String(), `"domains":["*.example.com","example.com"]`) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("valid renewal navigation refused: %d", w.Code)
	}
	for _, secret := range []string{`"private_key"`, `"csr"`, `"ciphertext"`, `"der"`, `"owner"`, `"location"`, nextTestPassword} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("selection leaked custody")
		}
	}
	fields.Set("expected_generation", strconv.FormatUint(gen-1, 10))
	if w := renewalNavigationCall(g, cookie, fields, "http://"+localHost); w.Code != 409 {
		t.Fatal("stale renewal navigation")
	}
}
