//go:build linux

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/dnsrecord"
)

func operatorDNSGate(t *testing.T) (*gate, *http.Cookie) {
	t.Helper()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private fixture directory")
	}
	destination := filepath.Join(dir, "synthetic-operator-dns.json")
	command := exec.Command("go", "test", "../../internal/instanceaccess", "-run=^TestGenerateOperatorDNSGateFixture$", "-count=1")
	command.Env = append(os.Environ(), "ROOTWELL_OPERATOR_DNS_FIXTURE="+destination)
	if command.Run() != nil {
		t.Fatal("private operator fixture failed")
	}
	body, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	var f struct{ Access, Image []byte }
	if json.Unmarshal(body, &f) != nil {
		t.Fatal("operator fixture invalid")
	}
	defer clear(f.Access)
	defer clear(f.Image)
	path := filepath.Join(dir, "access.json")
	if os.WriteFile(path, f.Access, 0600) != nil || os.WriteFile(filepath.Join(dir, "inventory.json"), f.Image, 0600) != nil {
		t.Fatal("private operator fixture store")
	}
	g, err := newGate(path, testWorkbenchAssets(t), localHost)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"a sufficiently long installation password"}`, nil))
	return g, cookie
}

func TestLinuxDNSMaintenanceAPIFreshScopeNoWriteAndNoCounterReset(t *testing.T) {
	g, cookie := operatorDNSGate(t)
	const password = "a sufficiently long installation password"
	body := strings.Replace(dnsMaintenanceInput, nextTestPassword, password, 1)
	calls := 0
	g.dnsConnect = func(_ context.Context, permit func() bool, _ []byte, scope dnsrecord.Scope, saved dnsrecord.State, cleanup, read bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		calls++
		if !permit() || !read || cleanup || saved.State != "creating" || scope.Name != "_acme-challenge.example.com" || checkpoint(saved) == nil {
			t.Fatal("operator endpoint acquired write")
		}
		return dnsrecord.State{State: "created", ID: strings.Repeat("c", 32)}, nil
	}
	for _, bad := range []struct {
		body string
		code int
	}{{strings.Replace(body, password, "incorrect-password", 1), 401}, {strings.Replace(body, `"reviewed":true`, `"reviewed":false`, 1), 400}, {strings.Replace(body, `operator-dns-read-only`, `session-renewal`, 1), 400}, {strings.TrimSuffix(dnsAddInput, "}") + `,"expected_generation":11}`, 400}} {
		if w := dnsAPICall(g, "maintenance", bad.body, cookie); w.Code != bad.code || calls != 0 {
			t.Fatal("operator consent/auth refused incorrectly", w.Code)
		}
	}
	w := dnsAPICall(g, "maintenance", body, cookie)
	var out dnsOperationOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || calls != 1 || out.Generation != 13 || !out.Network || out.Records[0].State != "created" || out.Records[0].Attempts != 1 || out.Records[0].Maintenance != nil {
		t.Fatal("valid operator result refused", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), password) || strings.Contains(w.Body.String(), "synthetic-only-credential") {
		t.Fatal("operator output leaked secret")
	}
	if w := dnsAPICall(g, "maintenance", body, cookie); w.Code != 409 || calls != 1 {
		t.Fatal("old operator grant replayed", w.Code)
	}
	r := httptest.NewRequest("GET", "http://"+localHost+"/", nil)
	r.AddCookie(cookie)
	_, ready := g.currentSession(r)
	if !ready {
		t.Fatal("operator check changed login")
	}
}
