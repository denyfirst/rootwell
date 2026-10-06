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
	for _, path := range []string{"/inventory", "/inventory-import.js", "/inventory-engine.js"} {
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
	}
}
