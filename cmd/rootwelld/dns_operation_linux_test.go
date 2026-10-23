//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func dnsAPICall(g *gate, mode, body string, cookie *http.Cookie) *orderRecorder {
	r := httptest.NewRequest("POST", "http://"+localHost+"/api/acme/dns/"+mode, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://"+localHost)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("X-Rootwell-Request", "1")
	r.AddCookie(cookie)
	w := &orderRecorder{ResponseRecorder: httptest.NewRecorder()}
	g.ServeHTTP(w, r)
	return w
}

func dnsAPIFixture(t *testing.T) (*gate, *http.Cookie, string, session) {
	t.Helper()
	g, cookie, path, s := registeredDNSGate(t)
	if _, _, err := instanceaccess.ChangeCloudflareConfig(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, 4, "0123456789abcdef0123456789abcdef", "example.com", []byte("synthetic-only-credential-not-a-real-token-1234567890"), false, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	g.orderConnect = func(_ context.Context, _ func() bool, _ crypto.Signer, _, _ string, _ []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		if err := checkpoint(apiDNS().URL); err != nil {
			return acmeorder.Instructions{}, err
		}
		return apiDNS(), nil
	}
	if w := orderCall(g, "start", orderRequest("5", true), cookie); w.Code != 200 {
		t.Fatal("DNS fixture request", w.Code)
	}
	at := g.now().Add(time.Minute)
	g.now = func() time.Time { return at }
	return g, cookie, path, s
}

func TestLinuxDNSAPIReauthGenerationBudgetsAndExactLockedCreateCleanup(t *testing.T) {
	g, cookie, path, s := dnsAPIFixture(t)
	defer clear(s.dataKey[:])
	calls := 0
	g.dnsConnect = func(_ context.Context, permit func() bool, token []byte, scope dnsrecord.Scope, saved dnsrecord.State, cleanup, readOnly bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		calls++
		image, _ := os.ReadFile(path)
		plan, gen, err := inventorystore.ReadStagingDNSPlan(s.dataKey[:], s.installationID[:], image)
		if err != nil || !permit() || string(token) != "synthetic-only-credential-not-a-real-token-1234567890" || scope.ZoneID != "0123456789abcdef0123456789abcdef" || scope.Owner == "" || readOnly {
			t.Fatal("API changed secret/direction")
		}
		if !cleanup {
			if gen != 10 || plan.Records[0].State != "creating" || saved.State != "new" {
				t.Fatal("network before durable create")
			}
			if err := checkpoint(dnsrecord.State{State: "creating"}); err != nil {
				t.Fatal(err)
			}
			return dnsrecord.State{State: "created", ID: strings.Repeat("c", 32)}, nil
		}
		if gen != 12 || plan.Records[0].State != "deleting" || saved != (dnsrecord.State{State: "created", ID: strings.Repeat("c", 32)}) {
			t.Fatal("cleanup before durable owned intent")
		}
		if err := checkpoint(dnsrecord.State{State: "deleting", ID: saved.ID}); err != nil {
			t.Fatal(err)
		}
		return dnsrecord.State{State: "deleted"}, nil
	}
	w := dnsAPICall(g, "status", dnsStatusInput, cookie)
	var output dnsOperationOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || !output.CanPrepare || output.Generation != 8 || len(output.PendingDomains) != 2 || calls != 0 {
		t.Fatal("status did not expose local pending scope", w.Code)
	}
	before, _ := os.ReadFile(path)
	for _, tc := range []struct {
		mode, body string
		want       int
	}{{"add", strings.Replace(dnsAddInput, nextTestPassword, "wrong-sentinel", 1), 401}, {"add", strings.Replace(dnsAddInput, `"expected_generation":8`, `"expected_generation":7`, 1), 409}, {"cleanup", strings.TrimSuffix(dnsAddInput, "}") + `,"exclusive":true}`, 409}} {
		w := dnsAPICall(g, tc.mode, tc.body, cookie)
		if w.Code != tc.want || calls != 0 {
			t.Fatal("refused API reached provider", w.Code)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("refusal wrote DNS state")
		}
	}
	if w := accountCall(g, "POST", "/api/acme/dns/add", dnsAddInput, cookie, "http://"+localHost, true); w.Code != 503 || calls != 0 {
		t.Fatal("unbounded writer accepted")
	}
	w = dnsAPICall(g, "add", dnsAddInput, cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Generation != 11 || output.Records[0].State != "created" || !output.Network || calls != 1 {
		t.Fatal("legitimate API add failed", w.Code, w.Body.String())
	}
	for _, sentinel := range []string{nextTestPassword, "synthetic-only-credential", "0123456789abcdef", strings.Repeat("c", 32), "rootwell-acme-v1-"} {
		if strings.Contains(w.Body.String(), sentinel) {
			t.Fatal("secret/provider identity reflected")
		}
	}
	cleanupBody := strings.Replace(dnsAddInput, `"expected_generation":8`, `"expected_generation":11`, 1)
	if w := dnsAPICall(g, "cleanup", cleanupBody, cookie); w.Code != 400 || calls != 1 {
		t.Fatal("cleanup lacked exclusive concurrency consent")
	}
	cleanupBody = strings.TrimSuffix(cleanupBody, "}") + `,"exclusive":true}`
	if w := dnsAPICall(g, "cleanup", cleanupBody, cookie); w.Code != 429 || calls != 1 {
		t.Fatal("provider shared cooldown bypassed")
	}
	at := g.now().Add(time.Minute)
	g.now = func() time.Time { return at }
	w = dnsAPICall(g, "cleanup", cleanupBody, cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Generation != 13 || output.Records[0].State != "deleted" || calls != 2 {
		t.Fatal("legitimate cleanup failed", w.Code, w.Body.String())
	}
}

func TestLinuxDNSAPIUnknownCreateNoReplayAndLogout(t *testing.T) {
	g, cookie, _, s := dnsAPIFixture(t)
	defer clear(s.dataKey[:])
	calls := 0
	g.dnsConnect = func(_ context.Context, _ func() bool, _ []byte, _ dnsrecord.Scope, _ dnsrecord.State, _, _ bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		calls++
		if err := checkpoint(dnsrecord.State{State: "creating"}); err != nil {
			t.Fatal(err)
		}
		return dnsrecord.State{}, errors.New("provider-secret-sentinel")
	}
	w := dnsAPICall(g, "add", dnsAddInput, cookie)
	var output dnsOperationOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Records[0].State != "creating" || output.Records[0].Attempts != 1 || strings.Contains(w.Body.String(), "sentinel") {
		t.Fatal("unknown provider result not retained")
	}
	retry := strings.Replace(dnsAddInput, `"expected_generation":8`, `"expected_generation":11`, 1)
	for _, mode := range []string{"add", "check"} {
		if w := dnsAPICall(g, mode, retry, cookie); w.Code != 409 || calls != 1 {
			t.Fatal("uncertain replay/early check authorized")
		}
	}
	call(g, "DELETE", "/api/session", "", cookie)
	if w := dnsAPICall(g, "check", retry, cookie); w.Code != 401 || calls != 1 {
		t.Fatal("logout retained DNS authority")
	}
}
