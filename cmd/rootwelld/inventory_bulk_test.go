package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

func TestInventoryBulkAssetsRemainBehindReadyAccess(t *testing.T) {
	g, _ := testGate(t)
	revision, err := instanceaccess.Revision(g.accessPath)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := g.issueSession(w, false, revision, nil, nil); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, w)
	setup := httptest.NewRecorder()
	if err := g.issueSession(setup, true, revision, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/inventory", "/inventory-import.js", "/inventory-engine.js", "/inventory-lifecycle.js"} {
		anonymous := call(g, "GET", path, "", nil)
		if anonymous.Code != http.StatusSeeOther || anonymous.Header().Get("Location") != "/login" {
			t.Fatal("anonymous access to bulk assets")
		}
		setupOnly := call(g, "GET", path, "", sessionCookie(t, setup))
		if setupOnly.Code != http.StatusSeeOther || setupOnly.Header().Get("Location") != "/setup" {
			t.Fatal("setup access to bulk assets")
		}
		ready := call(g, "GET", path, "", cookie)
		if ready.Code != http.StatusOK || ready.Header().Get("Cache-Control") != "no-store" || ready.Body.Len() == 0 {
			t.Fatal("ready bulk asset unavailable")
		}
		if call(g, "POST", path, "{}", cookie).Code != http.StatusMethodNotAllowed ||
			call(g, "GET", path+"?certificate=not-allowed", "", cookie).Code != http.StatusBadRequest {
			t.Fatal("bulk asset accepts write or data query")
		}
		if path == "/inventory" && (!strings.Contains(ready.Body.String(), "multiple required") || !strings.Contains(ready.Body.String(), "Preview locally")) {
			t.Fatal("missing local-preview bulk UI")
		}
		if path == "/inventory" {
			assertInventoryWorkspace(t, ready)
		}
	}
}

// Test the actual authenticated response on every platform, not a mutable
// marketing heading. The Linux persistence test reuses the same boundary gate.
func assertInventoryWorkspace(t *testing.T, page *httptest.ResponseRecorder) {
	t.Helper()
	if page.Code != http.StatusOK || page.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("inventory workspace unavailable: HTTP %d", page.Code)
	}
	body := page.Body.String()
	for _, required := range []string{
		`class="workspace inventory-workspace"`, `href="/style.css"`,
		`href="/inventory" aria-current="page"`, `aria-label="Storage boundary"`,
		"Only when you press Save", "stored encrypted", "No PFX or private keys",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("inventory workspace missing required boundary %q", required)
		}
	}
	if strings.Contains(body, "No certificate uploads") {
		t.Fatal("inventory workspace misrepresented explicit server upload as offline")
	}
}
