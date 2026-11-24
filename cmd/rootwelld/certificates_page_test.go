package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Certificates, the home page, and the scripts it runs are served only to a
// ready session; the PFX reader runs in a worker with no network and no
// further workers.
func TestCertificatesPageAndItsScriptsRemainBehindReadyAccess(t *testing.T) {
	g, cookie, e := readyGate(t)
	// The password alone, without the phone code, is not signed in.
	codeStage := e.passwordStep(t, testPassword)
	for _, path := range []string{"/certificates", "/certificates.js", "/ui.js", "/certificate-pfx.js", "/certificate-pfx-worker.js"} {
		anonymous := call(g, "GET", path, "", nil)
		if anonymous.Code != http.StatusSeeOther || anonymous.Header().Get("Location") != "/login" {
			t.Fatalf("anonymous access to %s", path)
		}
		passwordOnly := call(g, "GET", path, "", codeStage)
		if passwordOnly.Code != http.StatusSeeOther || passwordOnly.Header().Get("Location") != "/login" {
			t.Fatalf("code-stage access to %s: %d", path, passwordOnly.Code)
		}
		ready := call(g, "GET", path, "", cookie)
		if ready.Code != http.StatusOK || ready.Header().Get("Cache-Control") != "no-store" || ready.Body.Len() == 0 {
			t.Fatalf("%s unavailable to a ready session", path)
		}
		if path == "/certificate-pfx-worker.js" && (!strings.Contains(ready.Header().Get("Content-Security-Policy"), "connect-src 'none'") || !strings.Contains(ready.Header().Get("Content-Security-Policy"), "worker-src 'none'")) {
			t.Fatal("PFX import worker gained network or child-worker capability")
		}
		if call(g, "POST", path, "{}", cookie).Code != http.StatusMethodNotAllowed ||
			call(g, "GET", path+"?certificate=not-allowed", "", cookie).Code != http.StatusBadRequest {
			t.Fatalf("%s accepts a write or a data query", path)
		}
		if path == "/certificates" {
			assertCertificatesPage(t, ready)
		}
	}
}

// The page served is the Certificates page in the shared design, with the
// scripts it needs and nothing inline. The Linux store test reuses it.
func assertCertificatesPage(t *testing.T, page *httptest.ResponseRecorder) {
	t.Helper()
	if page.Code != http.StatusOK || page.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Certificates unavailable: HTTP %d", page.Code)
	}
	body := page.Body.String()
	for _, required := range []string{
		`<title>Certificates · Rootwell</title>`, `<link rel="stylesheet" href="/rootwell.css">`,
		`<a class="nav-item" href="/certificates" aria-current="page">`,
		`<script src="/certificate-pfx.js" defer></script>`, `<script src="/certificates.js" defer></script>`,
		`id="rail-sign-out"`,
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("Certificates lacks %q", required)
		}
	}
	if strings.Contains(body, ` style="`) || strings.Contains(body, "<script>") {
		t.Fatal("Certificates carries inline style or script")
	}
}
