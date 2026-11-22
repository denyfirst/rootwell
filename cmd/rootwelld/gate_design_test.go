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
	g, _ := testGate(t)
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

	setup := call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil)
	changed := call(g, "POST", "/api/password", `{"password":"`+initialTestPassword+`","next":"`+nextTestPassword+`"}`, sessionCookie(t, setup))
	if changed.Code != http.StatusNoContent {
		t.Fatalf("password change: %d", changed.Code)
	}
	ready := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	for route, cache := range map[string]string{
		"/rootwell.wasm": "no-cache", "/wasm_exec.js": "no-cache",
		"/app.js": "no-store", "/session.js": "no-store", "/theme.js": "no-store", "/": "no-store",
	} {
		w := call(g, "GET", route, "", ready)
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != cache {
			t.Errorf("%s: %d with Cache-Control %q, want %q", route, w.Code, w.Header().Get("Cache-Control"), cache)
		}
	}
}
