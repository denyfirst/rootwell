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
	fresh := call(g, "POST", "/api/fresh", `{"code":"`+e.code(t)+`"}`, c)
	if fresh.Code != http.StatusNoContent {
		t.Fatalf("fresh code: %d", fresh.Code)
	}
	c = sessionCookie(t, fresh)
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
	// A record in the clear would hold the name as a JSON string and the phone
	// seed as it is. The bare name is not looked for: three letters such as
	// "ada" turn up by chance in the vault's hex record keys and base64
	// ciphertext, in about one backup in 25.
	if body := w.Body.String(); strings.Contains(body, `"`+testName+`"`) || strings.Contains(body, e.seed) {
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

func TestTheBackupBufferStopsAtItsLimit(t *testing.T) {
	b := &cappedBuffer{limit: 4}
	if n, err := b.Write([]byte("abc")); err != nil || n != 3 {
		t.Fatalf("under the limit: %d %v", n, err)
	}
	if _, err := b.Write([]byte("de")); err == nil || !b.over || b.Len() != 3 {
		t.Fatalf("past the limit: over %v, %d bytes, %v", b.over, b.Len(), err)
	}
}

func TestOneBackupAtATimeAndOnlyToTheSessionThatAsked(t *testing.T) {
	g, c, _ := readyGate(t)
	g.backups <- struct{}{}
	if w := call(g, "POST", "/api/backup", `{}`, c); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("a second backup at once: %d", w.Code)
	}
	<-g.backups
	if w := call(g, "POST", "/api/backup", `{}`, c); w.Code != http.StatusOK {
		t.Fatalf("a backup once the first is done: %d", w.Code)
	}
}
