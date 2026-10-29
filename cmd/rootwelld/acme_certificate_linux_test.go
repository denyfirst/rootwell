//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func TestLinuxCertificateAPIInteractiveAuthorityNoReplayAndReadOnlyResult(t *testing.T) {
	g, cookie, path, s := registeredDNSGate(t)
	defer clear(s.dataKey[:])
	advance := func() { at := g.now().Add(time.Minute + time.Second); g.now = func() time.Time { return at } }
	g.orderConnect = func(_ context.Context, _ func() bool, _ crypto.Signer, _, _ string, _ []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
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
	advance()
	g.validationConnect = func(_ context.Context, _ func() bool, _ crypto.Signer, _ string, saved acmeorder.Instructions, _ []string, _ bool) (acmeorder.Validation, error) {
		return acmeorder.Validation{URL: saved.URL, Expires: saved.Expires, OrderStatus: "ready", Statuses: []string{"valid", "valid"}}, nil
	}
	if w := orderCall(g, "validate", orderRequest("8", false), cookie); w.Code != 200 {
		t.Fatal("fixture validation refused")
	}
	calls := 0
	g.certificateConnect = func(context.Context, func() bool, crypto.Signer, string, string, string, []string, []byte, []byte, bool) (acmestaging.CertificateObservation, error) {
		calls++
		t.Error("refused request reached certificate connector")
		return acmestaging.CertificateObservation{}, nil
	}
	if w := orderCall(g, "issue", orderRequest("10", false), cookie); w.Code != 409 || calls != 0 {
		t.Fatal("missing prepared key issued certificate")
	}
	if w := orderCall(g, "prepare-key", orderRequest("10", false), cookie); w.Code != 200 {
		t.Fatal("fixture key refused")
	}
	before, _ := os.ReadFile(path)
	if w := orderCall(g, "issue", orderRequest("10", false), cookie); w.Code != 409 {
		t.Fatal("stale generation issued")
	}
	if w := orderCall(g, "certificate-refresh", orderRequest("11", false), cookie); w.Code != 409 {
		t.Fatal("read without intent reached connector")
	}
	if w := orderCall(g, "issue", strings.Replace(orderRequest("11", false), nextTestPassword, "wrong sentinel", 1), cookie); w.Code != 401 {
		t.Fatal("wrong password issued")
	}
	if w := accountCall(g, "POST", "/api/acme/order/issue", orderRequest("11", false), cookie, "http://"+localHost, true); w.Code != 503 {
		t.Fatal("unbounded response issued")
	}
	if w := orderCall(g, "issue", orderRequest("11", false), cookie); w.Code != 429 {
		t.Fatal("provider cooldown bypassed")
	}
	after, _ := os.ReadFile(path)
	if calls != 0 || !bytes.Equal(before, after) {
		t.Fatal("preflight refusal mutated/contacted CA")
	}
	advance()
	var originalCSR, originalPrivate []byte
	defer func() { clear(originalPrivate); clear(originalCSR) }()
	g.certificateConnect = func(ctx context.Context, permit func() bool, _ crypto.Signer, account, order, expiry string, names []string, private, csr []byte, readOnly bool) (acmestaging.CertificateObservation, error) {
		calls++
		image, err := os.ReadFile(path)
		st, gen, se := inventorystore.ReadStagingIssuance(s.dataKey[:], s.installationID[:], image)
		if err != nil || se != nil || gen != 12 || st.State != "issuance-pending" || readOnly || ctx.Err() != nil || !permit() || account != apiAccount || order != apiDNS().URL || expiry == "" || len(names) != 2 {
			t.Fatal("finalize not scoped after durable intent")
		}
		originalCSR, originalPrivate = bytes.Clone(csr), bytes.Clone(private)
		return acmestaging.CertificateObservation{}, errors.New("private provider sentinel")
	}
	w := orderCall(g, "issue", orderRequest("11", false), cookie)
	if w.Code != 503 || calls != 1 || strings.Contains(w.Body.String(), "sentinel") || strings.Contains(w.Body.String(), "No certificate was issued") {
		t.Fatal("uncertain issuance misreported")
	}
	for _, mode := range []string{"issue", "prepare-key", "validate", "refresh", "ack", "resume"} {
		if w := orderCall(g, mode, orderRequest("12", false), cookie); w.Code != 409 || calls != 1 {
			t.Fatal("pending intent allowed replay/old mutation")
		}
	}
	w = orderCall(g, "status", orderStatusInput, cookie)
	var output orderOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Schema != "rootwell.acme.manual-dns.v9" || output.CanIssue || output.Network || output.Issuance.State != "issuance-pending" || output.Generation != 12 {
		t.Fatal("durable pending status incorrect")
	}
	advance()
	g.certificateConnect = func(ctx context.Context, permit func() bool, _ crypto.Signer, account, order, expiry string, _ []string, private, csr []byte, readOnly bool) (acmestaging.CertificateObservation, error) {
		calls++
		if !readOnly || !permit() || ctx.Err() != nil || account != apiAccount || order != apiDNS().URL || !bytes.Equal(private, originalPrivate) || !bytes.Equal(csr, originalCSR) {
			t.Fatal("reconciliation changed key/order/CSR/direction")
		}
		return acmestaging.CertificateObservation{State: "processing", Expires: expiry}, nil
	}
	w = orderCall(g, "certificate-refresh", orderRequest("12", false), cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || !output.Network || output.CanIssue || output.Generation != 13 || output.Issuance.State != "awaiting-certificate" || calls != 2 {
		t.Fatal("interactive read result refused")
	}
	for _, secret := range []string{"private_key", "csr", apiAccount, apiDNS().URL, "sentinel"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("secret/provider URL leaked")
		}
	}
	// Cancellation after a response has arrived must leave durable pending
	// custody and cannot announce success or grant another first attempt.
	advance()
	before, _ = os.ReadFile(path)
	g.certificateConnect = func(_ context.Context, _ func() bool, _ crypto.Signer, _, _, expiry string, _ []string, _, _ []byte, _ bool) (acmestaging.CertificateObservation, error) {
		calls++
		_ = call(g, "DELETE", "/api/session", "", cookie)
		return acmestaging.CertificateObservation{State: "processing", Expires: expiry}, nil
	}
	if w := orderCall(g, "certificate-refresh", orderRequest("13", false), cookie); w.Code != 503 {
		t.Fatal("logged-out result published")
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("logged-out result saved")
	}
}
