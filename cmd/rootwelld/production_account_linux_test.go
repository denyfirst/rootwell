//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

func TestLinuxProductionAccountAPIReauthNoNetworkNoPromotionOrReplacement(t *testing.T) {
	g, cookie, path := accountGateFixture(t)
	prior := http.DefaultTransport
	http.DefaultTransport = refuseACMETransport{}
	t.Cleanup(func() { http.DefaultTransport = prior })
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body string
		code int
	}{
		{strings.Replace(productionAccountPrepareInput, nextTestPassword, "wrong-secret-sentinel", 1), 401},
		{strings.Replace(productionAccountPrepareInput, `"expected_generation":1`, `"expected_generation":2`, 1), 409},
	} {
		w := accountCall(g, "POST", "/api/acme/production-account/prepare", tc.body, cookie, "http://"+localHost, true)
		if w.Code != tc.code || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("production API reauth/stale bypass", w.Code)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refused production API wrote")
		}
	}
	w := accountCall(g, "POST", "/api/acme/production-account/prepare", productionAccountPrepareInput, cookie, "http://"+localHost, true)
	var result accountOutput
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Provider != "letsencrypt-production" || result.Generation != 2 || !result.Saved || result.AccountCreated || result.TermsAccepted || result.CanIssue || result.NetworkUsed || result.Registration != "not-registered" || strings.Contains(w.Body.String(), nextTestPassword) || strings.Contains(w.Body.String(), "private_key") {
		t.Fatal("production local preparation failed or gained authority", w.Code)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w = accountCall(g, "POST", "/api/acme/production-account/prepare", strings.Replace(productionAccountPrepareInput, `"expected_generation":1`, `"expected_generation":2`, 1), cookie, "http://"+localHost, true)
	if w.Code != 409 {
		t.Fatal("production account overwritten", w.Code)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(saved, after) {
		t.Fatal("duplicate production key changed image")
	}
	w = accountCall(g, "POST", "/api/acme/account/status", accountStatusInput, cookie, "http://"+localHost, true)
	var stage accountOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &stage) != nil || stage.State != "not-prepared" || stage.Saved || stage.Generation != 2 {
		t.Fatal("production account promoted to staging")
	}
	key, id, err := instanceaccess.OpenWithIdentity(g.accessPath, nextTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	rev, err := instanceaccess.Revision(g.accessPath)
	if err != nil {
		t.Fatal(err)
	}
	actual, gen, err := instanceaccess.ReadProductionAccount(g.accessPath, key, id, rev)
	if err != nil || actual.Fingerprint != result.Fingerprint || gen != 2 {
		t.Fatal("API did not persist separate account", err)
	}
}
