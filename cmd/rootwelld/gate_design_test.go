package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

// The typeface is public and served before sign-in, so the sign-in page is
// drawn like every other page; the engine is public code the browser may keep
// and revalidate (audit RW-21); everything else stays no-store.
func TestTheTypefaceIsPublicAndTheEngineRevalidates(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	g := e.g
	font := call(g, "GET", "/schibsted-grotesk.woff2", "", nil)
	sum := sha256.Sum256(font.Body.Bytes())
	if font.Code != http.StatusOK || font.Header().Get("Content-Type") != "font/woff2" ||
		font.Header().Get("Cache-Control") != "no-cache" ||
		hex.EncodeToString(sum[:]) != "4c8b93f431d462c696e12b9d6a033feb3394d36e66e781357c496b95d8a75e05" {
		t.Fatalf("typeface: %d %q %q %x", font.Code, font.Header().Get("Content-Type"), font.Header().Get("Cache-Control"), sum)
	}
	if csp := font.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "font-src 'self';") {
		t.Fatalf("fonts are not limited to this server: %q", csp)
	}
	if w := call(g, "POST", "/schibsted-grotesk.woff2", "", nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("typeface accepted a POST: %d", w.Code)
	}
	for _, route := range []string{"/session.js", "/rootwell.wasm"} {
		if w := call(g, "GET", route, "", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
			t.Fatalf("%s was served before sign-in: %d", route, w.Code)
		}
	}

	ready := e.signIn(t)
	for route, cache := range map[string]string{
		"/rootwell.wasm": "no-cache", "/wasm_exec.js": "no-cache",
		"/certificates": "no-store", "/certificates.js": "no-store", "/session.js": "no-store", "/theme.js": "no-store",
	} {
		w := call(g, "GET", route, "", ready)
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != cache {
			t.Errorf("%s: %d with Cache-Control %q, want %q", route, w.Code, w.Header().Get("Cache-Control"), cache)
		}
	}
}

// Every page, signed in or not, is served under one strict policy: scripts,
// styles, images, fonts and connections only from this server, the engine
// allowed to compile, and nothing inline.
func TestEveryPageIsServedUnderTheStrictContentSecurityPolicy(t *testing.T) {
	g, ready, _ := readyGate(t)
	pages := map[string]*http.Cookie{"/login": nil, "/setup": nil, "/certificates": ready, "/website-check": ready, "/inspect": ready,
		"/convert": ready, "/request": ready, "/account": ready}
	for route, cookie := range pages {
		w := call(g, "GET", route, "", cookie)
		csp := w.Header().Get("Content-Security-Policy")
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d", route, w.Code)
			continue
		}
		for _, directive := range []string{"default-src 'none'", "style-src 'self';", "script-src 'self' 'wasm-unsafe-eval';",
			"img-src 'self';", "connect-src 'self';", "font-src 'self';", "object-src 'none'", "worker-src 'self'",
			"base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, directive) {
				t.Errorf("%s: the policy lacks %q", route, directive)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "'unsafe-eval'") || strings.Contains(csp, "http:") || strings.Contains(csp, "https:") {
			t.Errorf("%s: the policy allows inline, eval or another origin: %q", route, csp)
		}
		if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: framing, referrer or sniffing is not refused", route)
		}
	}
}
