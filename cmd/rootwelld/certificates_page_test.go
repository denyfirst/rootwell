package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

// Certificates, the home page, and the scripts it runs are served only to a
// ready session; the PFX reader runs in a worker with no network and no
// further workers.
func TestCertificatesPageAndItsScriptsRemainBehindReadyAccess(t *testing.T) {
	g, _ := testGate(t)
	revision, err := instanceaccess.Revision(g.accessPath)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := g.issueSession(w, false, revision); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, w)
	setup := httptest.NewRecorder()
	if err := g.issueSession(setup, true, revision); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/certificates", "/certificates.js", "/ui.js", "/certificate-pfx.js", "/certificate-pfx-worker.js"} {
		anonymous := call(g, "GET", path, "", nil)
		if anonymous.Code != http.StatusSeeOther || anonymous.Header().Get("Location") != "/login" {
			t.Fatalf("anonymous access to %s", path)
		}
		setupOnly := call(g, "GET", path, "", sessionCookie(t, setup))
		if setupOnly.Code != http.StatusSeeOther || setupOnly.Header().Get("Location") != "/setup" {
			t.Fatalf("setup access to %s", path)
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
