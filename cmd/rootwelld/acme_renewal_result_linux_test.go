//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/denyfirst/rootwell/internal/acmeorder"
)

func TestLinuxRenewalResultAPIIsPublicReadOnlyAndSessionBound(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "synthetic-renewal-gate.json")
	command := exec.Command("go", "test", "../../internal/instanceaccess", "-run=^TestGenerateRenewalResultGateFixture$", "-count=1")
	command.Env = append(os.Environ(), "ROOTWELL_RENEWAL_RESULT_GATE_FIXTURE="+destination)
	if err := command.Run(); err != nil {
		t.Fatal("private renewal gate fixture failed")
	}
	body, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	var fixture struct {
		Access, Image []byte
		Fingerprint   string
	}
	if json.Unmarshal(body, &fixture) != nil {
		t.Fatal("invalid encrypted fixture")
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
	calls := 0
	g.orderConnect = func(context.Context, func() bool, crypto.Signer, string, string, []string, func(string) error) (acmeorder.Instructions, error) {
		calls++
		t.Error("result read contacted CA")
		return acmeorder.Instructions{}, nil
	}
	w := orderCall(g, "status", orderStatusInput, cookie)
	var result orderOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Schema != "rootwell.acme.manual-dns.v8" || result.Generation != 23 || result.Network || result.CanIssue || result.Issuance.State != "certificate-saved" || result.RenewalResult == nil || result.RenewalResult.OriginalFingerprint != fixture.Fingerprint || result.RenewalResult.NewFingerprint == fixture.Fingerprint || !result.RenewalResult.ExpiryExtended || calls != 0 {
		t.Fatal("renewal result API unavailable or wrong authority", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("result could be cached")
	}
	for _, secret := range [][]byte{[]byte("PRIVATE KEY"), []byte("private_key"), []byte("acme/order"), []byte(nextTestPassword)} {
		if bytes.Contains(w.Body.Bytes(), secret) {
			t.Fatal("result leaked secret/internal URI")
		}
	}
	if w := orderCall(g, "status", orderStatusInput, nil); w.Code != 401 {
		t.Fatal("anonymous result exposed")
	}
	if w := orderCall(g, "status", `{"provider":"letsencrypt-staging","expected_generation":23}`, cookie); w.Code != 400 {
		t.Fatal("malformed result request accepted")
	}
	after, err := os.ReadFile(store)
	if err != nil || !bytes.Equal(after, fixture.Image) {
		t.Fatal("result read changed encrypted image")
	}
	// Corrupt even an unrelated authenticated part; a complete result must not
	// be derived from an order/issuance alone when the full image is invalid.
	if err := os.WriteFile(store, []byte("secret-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	w = orderCall(g, "status", orderStatusInput, cookie)
	if w.Code == 200 || bytes.Contains(w.Body.Bytes(), []byte("secret-sentinel")) || bytes.Contains(w.Body.Bytes(), []byte("renewal_result")) {
		t.Fatal("invalid image exposed partial comparison")
	}
}
