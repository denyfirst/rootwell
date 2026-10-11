//go:build linux

package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func TestLinuxDNSValidationAPIExactAuthorityUncertaintyNoReplayAndTruth(t *testing.T) {
	g, cookie, path, s := registeredDNSGate(t)
	defer clear(s.dataKey[:])
	g.orderConnect = func(_ context.Context, _ func() bool, _ crypto.Signer, _, _ string, _ []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		if err := checkpoint(apiDNS().URL); err != nil {
			return acmeorder.Instructions{}, err
		}
		return apiDNS(), nil
	}
	if w := orderCall(g, "start", orderRequest("4", true), cookie); w.Code != 200 {
		t.Fatal("fixture order failed")
	}
	if w := orderCall(g, "ack", orderRequest("7", false), cookie); w.Code != 200 {
		t.Fatal("fixture ack failed")
	}
	advance := func() { at := g.now().Add(time.Minute + time.Second); g.now = func() time.Time { return at } }
	advance()
	calls := 0
	g.validationConnect = func(_ context.Context, permit func() bool, signer crypto.Signer, account string, saved acmeorder.Instructions, names []string, refresh bool) (acmeorder.Validation, error) {
		calls++
		image, _ := os.ReadFile(path)
		status, gen, err := inventorystore.ReadStagingOrder(s.dataKey[:], s.installationID[:], image)
		if err != nil || gen != 9 || status.State != "validation-pending" || signer == nil || !permit() || account != apiAccount || saved.URL != apiDNS().URL || len(names) != 2 || refresh {
			t.Fatal("validation before intent/exact authority")
		}
		return acmeorder.Validation{}, errors.New("CA-secret-sentinel")
	}
	before, _ := os.ReadFile(path)
	for _, tc := range []struct {
		mode, input string
		code        int
	}{{"validate", orderRequest("7", false), 409}, {"refresh", orderRequest("8", false), 409}, {"validate", strings.Replace(orderRequest("8", false), nextTestPassword, "wrong sentinel", 1), 401}} {
		if w := orderCall(g, tc.mode, tc.input, cookie); w.Code != tc.code || calls != 0 {
			t.Fatal("refused validation reached connector")
		}
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("refusal wrote")
	}
	if w := accountCall(g, "POST", "/api/acme/order/validate", orderRequest("8", false), cookie, "http://"+localHost, true); w.Code != 503 || calls != 0 {
		t.Fatal("unbounded writer accepted")
	}
	if w := orderCall(g, "validate", orderRequest("8", false), cookie); w.Code != 503 || calls != 1 || strings.Contains(w.Body.String(), "sentinel") {
		t.Fatal("unknown validation leaked or succeeded")
	}
	if w := orderCall(g, "validate", orderRequest("9", false), cookie); w.Code != 409 || calls != 1 {
		t.Fatal("Accept replay authorized")
	}
	if w := orderCall(g, "resume", orderRequest("9", false), cookie); w.Code != 409 {
		t.Fatal("old route reset validation")
	}
	advance()
	g.validationConnect = func(_ context.Context, _ func() bool, _ crypto.Signer, _ string, saved acmeorder.Instructions, _ []string, refresh bool) (acmeorder.Validation, error) {
		calls++
		if !refresh {
			t.Fatal("refresh enabled Accept")
		}
		return acmeorder.Validation{URL: saved.URL, Expires: saved.Expires, OrderStatus: "ready", Statuses: []string{"valid", "valid"}}, nil
	}
	w := orderCall(g, "refresh", orderRequest("9", false), cookie)
	var output orderOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.State != "domain-verified" || output.Generation != 11 || !output.DomainVerified || !output.Network || output.CanIssue || calls != 2 {
		t.Fatalf("truth/refresh refused %d", w.Code)
	}
	for _, secret := range []string{apiAccount, apiDNS().URL, "private_key", "sentinel"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("internal data leaked")
		}
	}
	if w := orderCall(g, "status", orderStatusInput, cookie); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Network || !output.DomainVerified || calls != 2 {
		t.Fatal("local status caused I/O")
	}
	advance()
	g.validationConnect = func(_ context.Context, _ func() bool, _ crypto.Signer, _ string, saved acmeorder.Instructions, _ []string, _ bool) (acmeorder.Validation, error) {
		g.mu.Lock()
		delete(g.sessions, sha256.Sum256([]byte(cookie.Value)))
		g.mu.Unlock()
		return acmeorder.Validation{URL: saved.URL, Expires: saved.Expires, OrderStatus: "ready", Statuses: []string{"valid", "valid"}}, nil
	}
	if w := orderCall(g, "refresh", orderRequest("11", false), cookie); w.Code != 503 || strings.Contains(w.Body.String(), "domain_verified") {
		t.Fatal("revoked result published")
	}
}
