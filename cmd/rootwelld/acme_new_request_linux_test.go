//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func TestLinuxNewRequestAPIFreshAuthLocalCloseAndDistinctNextOrder(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	fixturePath := filepath.Join(dir, "synthetic-closed-gate.json")
	command := exec.Command("go", "test", "../../internal/instanceaccess", "-run=^TestGenerateClosedRequestGateFixture$", "-count=1")
	command.Env = append(os.Environ(), "ROOTWELL_CLOSED_GATE_FIXTURE="+fixturePath)
	if err := command.Run(); err != nil {
		t.Fatal("private gate fixture failed")
	}
	body, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	var fixture struct {
		Access, Image []byte
		Fingerprint   string
	}
	if json.Unmarshal(body, &fixture) != nil {
		t.Fatal("invalid fixture")
	}
	path := filepath.Join(dir, "access.json")
	store := filepath.Join(dir, "inventory.json")
	if err := os.WriteFile(path, fixture.Access, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store, fixture.Image, 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := newGate(path, testWorkbenchAssets(t), localHost)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	key, id, err := instanceaccess.OpenWithIdentity(path, nextTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	revision, err := instanceaccess.Revision(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	g.orderConnect = func(context.Context, func() bool, crypto.Signer, string, string, []string, func(string) error) (acmeorder.Instructions, error) {
		calls++
		t.Error("local closure contacted CA")
		return acmeorder.Instructions{}, nil
	}
	w := orderCall(g, "status", orderStatusInput, cookie)
	var output orderOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || !output.NewRequest.Available || output.NewRequest.Reason != "complete" || output.Generation != 13 {
		t.Fatalf("completed status refused: %d", w.Code)
	}
	assertRenewalNavigation(t, g, cookie, fixture.Fingerprint, 13)
	originalKey := output.CertificateKey
	before, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body string
		code int
	}{{orderRequest("12", false), 409}, {strings.Replace(orderRequest("13", false), nextTestPassword, "wrong test password", 1), 401}} {
		if w := orderCall(g, "close-request", tc.body, cookie); w.Code != tc.code {
			t.Fatal("stale/wrong password closure accepted")
		}
	}
	if w := accountCall(g, "POST", "/api/acme/order/close-request", orderRequest("13", false), cookie, "http://"+localHost, true); w.Code != 503 {
		t.Fatal("unbounded response allowed close")
	}
	g.derive <- struct{}{}
	w = orderCall(g, "close-request", orderRequest("13", false), cookie)
	<-g.derive
	if w.Code != 503 {
		t.Fatal("busy derivation allowed close")
	}
	after, _ := os.ReadFile(store)
	if !bytes.Equal(before, after) || calls != 0 {
		t.Fatal("preflight refusal changed or contacted provider")
	}
	var oldHash [32]byte
	if err := instanceaccess.WithCertificate(path, key, id, revision, 13, fixture.Fingerprint, func(_ publicinventory.Record, private []byte) error { oldHash = sha256.Sum256(private); return nil }); err != nil {
		t.Fatal(err)
	}
	w = orderCall(g, "close-request", orderRequest("13", false), cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Schema != "rootwell.acme.manual-dns.v9" || output.NewRequest.ClosedCount != 1 || output.NewRequest.Reason != "not-started" || output.Generation != 14 || output.Network || output.Saved || output.CanIssue || output.CertificateKey.Prepared || output.Issuance.State != "not-started" || calls != 0 {
		t.Fatalf("valid local closure refused: %d", w.Code)
	}
	for _, secret := range []string{"private_key", "csr", "ciphertext", "/acme/order/", "sentinel"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("closure leaked internal scope")
		}
	}
	if w := orderCall(g, "close-request", orderRequest("14", false), cookie); w.Code != 409 {
		t.Fatal("closure repeated")
	}
	for _, mode := range []string{"issue", "certificate-refresh", "resume", "refresh", "prepare-key"} {
		if w := orderCall(g, mode, orderRequest("14", false), cookie); w.Code != 409 || calls != 0 {
			t.Fatal("closed old order regained authority")
		}
	}
	g.orderConnect = func(_ context.Context, permit func() bool, signer crypto.Signer, account, order string, names []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		calls++
		if !permit() || signer == nil || account != apiAccount || order != "" || len(names) != 2 {
			t.Fatal("new order used old scope")
		}
		info := apiDNS()
		body, err := os.ReadFile(store)
		if err != nil {
			t.Fatal(err)
		}
		pending, gen, err := inventorystore.ReadStagingOrder(key, id, body)
		if err != nil || gen != 15 || pending.State != "request-pending" || pending.RenewalSource != fixture.Fingerprint {
			t.Fatal("renewal network preceded bound durable intent")
		}
		info.URL = acmeorder.Origin + "/acme/order/1234/9999"
		if err := checkpoint(info.URL); err != nil {
			return acmeorder.Instructions{}, err
		}
		return info, nil
	}
	w = orderCall(g, "renew", renewalRequest("14", fixture.Fingerprint), cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Generation != 17 || output.RenewalSource != fixture.Fingerprint || !output.Network || output.NewRequest.ClosedCount != 1 || output.State != "dns-ready" || calls != 1 {
		t.Fatalf("distinct order failed: %d", w.Code)
	}
	if w := orderCall(g, "ack", orderRequest("17", false), cookie); w.Code != 200 {
		t.Fatal("new ack refused")
	}
	at := g.now().Add(time.Minute + time.Second)
	g.now = func() time.Time { return at }
	g.validationConnect = func(_ context.Context, _ func() bool, _ crypto.Signer, _ string, saved acmeorder.Instructions, _ []string, _ bool) (acmeorder.Validation, error) {
		return acmeorder.Validation{URL: saved.URL, Expires: saved.Expires, OrderStatus: "ready", Statuses: []string{"valid", "valid"}}, nil
	}
	if w := orderCall(g, "validate", orderRequest("18", false), cookie); w.Code != 200 {
		t.Fatal("new validation refused")
	}
	w = orderCall(g, "prepare-key", orderRequest("20", false), cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || !output.CertificateKey.Prepared || output.CertificateKey.Fingerprint == originalKey.Fingerprint || output.Generation != 21 {
		t.Fatal("new key was not independent")
	}
	if err := instanceaccess.WithCertificate(path, key, id, revision, 21, fixture.Fingerprint, func(r publicinventory.Record, private []byte) error {
		if sha256.Sum256(private) != oldHash || r.StagingOrigin == nil {
			t.Fatal("new order lost earlier pair")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
