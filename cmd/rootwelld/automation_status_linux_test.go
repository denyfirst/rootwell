//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestLinuxAutomationStatusAPINoNetworkMutationOrUnlockedBypass(t *testing.T) {
	g, cookie, path, s := dnsAPIFixture(t)
	defer clear(s.dataKey[:])
	route := "/api/automation/status"
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := accountCall(g, "POST", route, accountStatusInput, cookie, "http://"+localHost, true)
	var result automationStatusOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Schema != "rootwell.automation.status.v2" || result.Generation != 8 || result.NetworkUsed || result.AutomaticRenewal || result.Request != "active" || !result.AccountReady || !result.DNSSaved || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("overview not local/current", w.Code, w.Body.String())
	}
	for _, secret := range []string{"synthetic-only-credential", "PRIVATE KEY", "acme/order", nextTestPassword} {
		if bytes.Contains(w.Body.Bytes(), []byte(secret)) {
			t.Fatal("secret/internal metadata escaped")
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("status mutated store")
	}
	// Shared expensive-crypto budget still applies to whole-image reads.
	if !g.startDerivation() {
		t.Fatal("busy fixture")
	}
	if w := accountCall(g, "POST", route, accountStatusInput, cookie, "http://"+localHost, true); w.Code != 503 {
		t.Fatal("busy budget bypass")
	}
	<-g.derive
	call(g, "DELETE", "/api/session", "", cookie)
	if w := accountCall(g, "POST", route, accountStatusInput, cookie, "http://"+localHost, true); w.Code != 401 {
		t.Fatal("logout retained access")
	}
}
