package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/accountstore"
	"github.com/denyfirst/rootwell/internal/vault"
)

func TestTheInstallationPageSaysHowBrowsersReachRootwell(t *testing.T) {
	g, c, e := readyGate(t)
	if got := page(g, "/installation", nil); got != http.StatusSeeOther {
		t.Fatalf("the page before sign-in: %d", got)
	}
	if got := page(g, "/installation", c); got != http.StatusOK {
		t.Fatalf("the page: %d", got)
	}
	if w := call(g, "GET", "/api/installation", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("the facts before sign-in: %d", w.Code)
	}
	w := call(g, "GET", "/api/installation", "", c)
	var facts struct {
		Names        []string `json:"names"`
		Fingerprint  string   `json:"fingerprint"`
		ServingUntil string   `json:"serving_until"`
		Certificates int      `json:"certificates"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &facts) != nil {
		t.Fatalf("facts: %d %s", w.Code, w.Body)
	}
	if strings.Join(facts.Names, ",") != "localhost,rootwell.lan,127.0.0.1,::1,192.0.2.10" || facts.Fingerprint != e.serving.Fingerprint() ||
		facts.Certificates != 0 {
		t.Fatalf("facts: %+v", facts)
	}
	if until, err := time.Parse(time.RFC3339, facts.ServingUntil); err != nil || !until.Equal(e.serving.Certificate.Leaf.NotAfter.UTC()) {
		t.Fatalf("serving until %q: %v", facts.ServingUntil, err)
	}
}

func TestABackupNeedsAFreshCodeAndOpensWithTheInstanceKey(t *testing.T) {
	g, c, e := readyGate(t)
	e.clock.add(freshLife)
	if w := call(g, "POST", "/api/backup", `{}`, c); w.Code != http.StatusPreconditionRequired {
		t.Fatalf("a backup without a fresh code: %d", w.Code)
	}
	if w := call(g, "POST", "/api/fresh", `{"code":"`+e.code(t)+`"}`, c); w.Code != http.StatusNoContent {
		t.Fatalf("fresh code: %d", w.Code)
	}
	if w := apiCall(g, "POST", "/api/backup", `{}`, c, "https://evil.example:4180", true); w.Code != http.StatusForbidden {
		t.Fatalf("a backup asked by another site: %d", w.Code)
	}
	if w := call(g, "GET", "/api/backup", "", c); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("a backup by GET: %d", w.Code)
	}
	w := call(g, "POST", "/api/backup", `{}`, c)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(w.Header().Get("Content-Disposition"), `attachment; filename="rootwell-backup-`) || w.Body.Len() == 0 {
		t.Fatalf("backup: %d %v", w.Code, w.Header())
	}
	if strings.Contains(w.Body.String(), testName) || strings.Contains(w.Body.String(), e.seed) {
		t.Fatal("the backup holds the account in the clear")
	}
	// The copy is a whole vault: it opens with the instance key, and only so.
	restored := t.TempDir()
	if err := os.Chmod(restored, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(restored, "rootwell.db"), w.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	other, _ := vault.NewInstanceKey()
	if v, err := vault.Open(restored, other); err == nil {
		_ = v.Close()
		t.Fatal("another key opened the backup")
	}
	v, err := vault.Open(restored, e.key)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if a, err := accountstore.New(v, e.clock.now).Get(testName); err != nil || a.Name != testName {
		t.Fatalf("the account in the backup: %+v %v", a, err)
	}
}
