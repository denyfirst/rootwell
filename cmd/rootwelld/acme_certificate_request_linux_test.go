//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

func TestLinuxCertificateRequestAPIFreshAuthorityLocalOnlyAndNoReplacement(t *testing.T) {
	g, cookie, path, s := registeredDNSGate(t)
	defer clear(s.dataKey[:])
	calls := 0
	g.orderConnect = func(_ context.Context, _ func() bool, _ crypto.Signer, _, _ string, _ []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		calls++
		if err := checkpoint(apiDNS().URL); err != nil {
			return acmeorder.Instructions{}, err
		}
		return apiDNS(), nil
	}
	if w := orderCall(g, "start", orderRequest("4", true), cookie); w.Code != 200 {
		t.Fatal("fixture order refused")
	}
	if w := orderCall(g, "ack", orderRequest("7", false), cookie); w.Code != 200 {
		t.Fatal("fixture ack refused")
	}
	before, _ := os.ReadFile(path)
	if w := orderCall(g, "prepare-key", orderRequest("8", false), cookie); w.Code != 409 {
		t.Fatal("unverified domain generated a key")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("unverified request changed image")
	}
	at := g.now().Add(time.Minute + time.Second)
	g.now = func() time.Time { return at }
	g.validationConnect = func(_ context.Context, _ func() bool, _ crypto.Signer, _ string, saved acmeorder.Instructions, _ []string, _ bool) (acmeorder.Validation, error) {
		calls++
		return acmeorder.Validation{URL: saved.URL, Expires: saved.Expires, OrderStatus: "ready", Statuses: []string{"valid", "valid"}}, nil
	}
	if w := orderCall(g, "validate", orderRequest("8", false), cookie); w.Code != 200 {
		t.Fatal("fixture validation refused")
	}
	before, _ = os.ReadFile(path)
	for _, tc := range []struct {
		body string
		code int
	}{
		{orderRequest("9", false), 409}, {strings.Replace(orderRequest("10", false), nextTestPassword, "wrong sentinel", 1), 401},
	} {
		if w := orderCall(g, "prepare-key", tc.body, cookie); w.Code != tc.code {
			t.Fatal("invalid preparation authority accepted")
		}
	}
	if w := accountCall(g, "POST", "/api/acme/order/prepare-key", orderRequest("10", false), cookie, "http://"+localHost, true); w.Code != 503 {
		t.Fatal("unbounded response permitted custody")
	}
	g.derive <- struct{}{}
	w := orderCall(g, "prepare-key", orderRequest("10", false), cookie)
	<-g.derive
	if w.Code != 503 {
		t.Fatal("busy derivation permitted custody")
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(before, after) || calls != 2 {
		t.Fatal("refused request wrote or contacted provider")
	}
	// Provider cooldown is still active: local preparation must not use its gate.
	w = orderCall(g, "prepare-key", orderRequest("10", false), cookie)
	var output orderOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Schema != "rootwell.acme.manual-dns.v8" || output.Issuance.State != "not-started" || !output.CertificateKey.Prepared || output.Generation != 11 || !output.DomainVerified || output.Network || !output.CanIssue || calls != 2 {
		t.Fatalf("local preparation refused/truth wrong: %d", w.Code)
	}
	for _, secret := range []string{apiAccount, apiDNS().URL, "private_key", "csr", "sentinel"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("secret request material leaked")
		}
	}
	prepared := output.CertificateKey
	durable, _ := os.ReadFile(path)
	if w := orderCall(g, "prepare-key", orderRequest("11", false), cookie); w.Code != 409 {
		t.Fatal("repeat replaced key")
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(durable, after) {
		t.Fatal("duplicate preparation changed key/CSR")
	}
	w = orderCall(g, "status", orderStatusInput, cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.CertificateKey != prepared || output.Generation != 11 || output.Network || !output.CanIssue || calls != 2 {
		t.Fatal("status lost custody or gained network/issuance authority")
	}
	if _, _, err := instanceaccess.RunStagingIssuance(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, 11, false, func() bool { return true }, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (string, error) {
		return "processing", nil
	}); err != nil {
		t.Fatal("fixture issuance intent refused")
	}
	w = orderCall(g, "status", orderStatusInput, cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Issuance.State != "awaiting-certificate" || output.Generation != 13 || output.Network || output.CanIssue || output.CertificateKey != prepared {
		t.Fatal("v4 status lost issuance intent or granted authority")
	}
	durable, _ = os.ReadFile(path)
	for _, mode := range []string{"prepare-key", "refresh", "validate", "ack", "resume", "start"} {
		w = orderCall(g, mode, orderRequest("13", mode == "start"), cookie)
		if w.Code != 409 || calls != 2 {
			t.Fatal("old DNS/key action crossed issuance boundary")
		}
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(durable, after) {
		t.Fatal("blocked old action changed issuance intent")
	}
}
