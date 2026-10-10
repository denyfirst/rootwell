//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type orderRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *orderRecorder) SetWriteDeadline(at time.Time) error { w.deadline = at; return nil }
func orderCall(g *gate, mode, input string, cookie *http.Cookie) *orderRecorder {
	r := httptest.NewRequest("POST", "http://"+localHost+"/api/acme/order/"+mode, strings.NewReader(input))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://"+localHost)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("X-Rootwell-Request", "1")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := &orderRecorder{ResponseRecorder: httptest.NewRecorder()}
	g.ServeHTTP(w, r)
	return w
}
func registeredDNSGate(t *testing.T) (*gate, *http.Cookie, string, session) {
	t.Helper()
	g, cookie, path, s := preparedRegistrationGate(t)
	proof := registrationProof(t, g, cookie)
	g.registrationCreate = func(context.Context, func() bool, crypto.Signer, string) (string, bool, error) {
		return apiAccount, false, nil
	}
	if w := accountCall(g, "POST", "/api/acme/registration/register", registrationRequest(proof), cookie, "http://"+localHost, true); w.Code != 200 {
		t.Fatal("fixture registration failed")
	}
	at := g.now().Add(time.Minute + time.Second)
	g.now = func() time.Time { return at }
	return g, cookie, path, s
}
func apiDNS() acmeorder.Instructions {
	return acmeorder.Instructions{URL: acmeorder.Origin + "/acme/order/1234/5678", Expires: time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05Z"), Records: []acmeorder.TXT{{Domain: "*.example.com", Name: "_acme-challenge.example.com", Value: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Required: true}, {Domain: "example.com", Name: "_acme-challenge.example.com", Value: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), Required: true}}}
}

func TestLinuxManualDNSAPIReauthCooldownDurableUncertaintyResumeAndAck(t *testing.T) {
	g, cookie, path, s := registeredDNSGate(t)
	defer clear(s.dataKey[:])
	calls := 0
	before, _ := os.ReadFile(path)
	g.orderConnect = func(_ context.Context, permit func() bool, signer crypto.Signer, account, order string, names []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		calls++
		if !permit() || signer == nil || account != apiAccount || order != "" || len(names) != 2 {
			t.Fatal("invalid connector authority")
		}
		image, _ := os.ReadFile(path)
		state, gen, err := inventorystore.ReadStagingOrder(s.dataKey[:], s.installationID[:], image)
		if err != nil || state.State != "request-pending" || gen != 5 {
			t.Fatal("network preceded intent")
		}
		if err := checkpoint(apiDNS().URL); err != nil {
			t.Fatal(err)
		}
		return acmeorder.Instructions{}, errors.New("CA-secret-sentinel")
	}
	for _, tc := range []struct {
		input string
		want  int
	}{{strings.Replace(orderRequest("4", true), nextTestPassword, "wrong-secret-sentinel", 1), 401}, {orderRequest("3", true), 409}} {
		w := orderCall(g, "start", tc.input, cookie)
		if w.Code != tc.want || calls != 0 || strings.Contains(w.Body.String(), "sentinel") {
			t.Fatal("invalid authority reached CA")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("invalid authority wrote intent")
		}
	}
	g.directoryBusy = true
	if w := orderCall(g, "start", orderRequest("4", true), cookie); w.Code != 429 || calls != 0 {
		t.Fatal("busy provider bypassed")
	}
	g.directoryBusy = false
	w := orderCall(g, "start", orderRequest("4", true), cookie)
	if w.Code != 503 || calls != 1 || strings.Contains(w.Body.String(), "sentinel") || time.Until(w.deadline) > 31*time.Second || w.deadline.IsZero() {
		t.Fatalf("uncertain outcome misreported: %d", w.Code)
	}
	w = orderCall(g, "status", orderStatusInput, cookie)
	var status orderOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.State != "order-known" || status.Generation != 6 || status.CanIssue || status.DomainVerified || status.Network || strings.Contains(w.Body.String(), apiDNS().URL) {
		t.Fatal("safe status lost")
	}
	if w := orderCall(g, "start", orderRequest("6", true), cookie); w.Code != 409 || calls != 1 {
		t.Fatal("uncertain order recreated")
	}
	g.orderConnect = func(_ context.Context, permit func() bool, signer crypto.Signer, account, order string, names []string, _ func(string) error) (acmeorder.Instructions, error) {
		calls++
		if !permit() || signer == nil || account != apiAccount || order != apiDNS().URL || len(names) != 2 {
			t.Fatal("resume scope differs")
		}
		return apiDNS(), nil
	}
	if w := orderCall(g, "resume", orderRequest("6", false), cookie); w.Code != 429 || calls != 1 {
		t.Fatal("cooldown/shared budget bypassed")
	}
	at := g.now().Add(time.Minute + time.Second)
	g.now = func() time.Time { return at }
	w = orderCall(g, "resume", orderRequest("6", false), cookie)
	if w.Code != 200 || calls != 2 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.State != "dns-ready" || status.Generation != 7 || !status.Network || status.DomainVerified || status.CanIssue || len(status.Records) != 2 {
		t.Fatalf("saved order resume failed: %d", w.Code)
	}
	w = orderCall(g, "ack", orderRequest("7", false), cookie)
	if w.Code != 200 || calls != 2 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.State != "dns-acknowledged" || status.Generation != 8 || status.Network || status.DomainVerified || status.CanIssue {
		t.Fatal("local acknowledgement caused network or false verification")
	}
	if w := orderCall(g, "ack", orderRequest("8", false), cookie); w.Code != 409 || calls != 2 {
		t.Fatal("ack replay accepted")
	}
}

func TestLinuxManualDNSAPIRevocationAndUnboundedWriterRefusePublication(t *testing.T) {
	g, cookie, _, s := registeredDNSGate(t)
	defer clear(s.dataKey[:])
	calls := 0
	g.orderConnect = func(_ context.Context, _ func() bool, _ crypto.Signer, _, _ string, _ []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		calls++
		if err := checkpoint(apiDNS().URL); err != nil {
			t.Fatal(err)
		}
		g.mu.Lock()
		delete(g.sessions, sha256.Sum256([]byte(cookie.Value)))
		g.mu.Unlock()
		return apiDNS(), nil
	}
	// A writer lacking a write deadline cannot begin an order.
	if w := accountCall(g, "POST", "/api/acme/order/start", orderRequest("4", true), cookie, "http://"+localHost, true); w.Code != 503 || calls != 0 {
		t.Fatal("unbounded response acquired authority")
	}
	if w := orderCall(g, "start", orderRequest("4", true), cookie); w.Code != 503 || calls != 1 || strings.Contains(w.Body.String(), "value") {
		t.Fatal("revoked result published")
	}
}
