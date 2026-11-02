//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/renewalpolicy"
	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

func renewalJobFixture(t *testing.T) (*gate, *http.Cookie, string, string, session, inventorystore.RenewalCycle) {
	t.Helper()
	g, cookie, store, fp, s := timingAPIFixture(t)
	if _, _, err := instanceaccess.CloseStagingRequest(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, 13, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, gen, err := instanceaccess.ChangeCloudflareConfig(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, 14, strings.Repeat("a", 32), "example.com", []byte("synthetic-only-not-a-real-cloudflare-token-1234567890"), false, func() bool { return true }); err != nil || gen != 15 {
		t.Fatal("fixture config", err)
	}
	p, err := instanceaccess.ReadRenewalCycle(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, 15, fp)
	if err != nil {
		t.Fatal("fixture cycle", err)
	}
	return g, cookie, store, fp, s, p
}

func pastARI(t *testing.T) timingConnect {
	t.Helper()
	return func(_ context.Context, permit func() bool, der []byte) (renewalrecord.Observation, error) {
		if !permit() {
			t.Error("original session permission lost")
		}
		cid, err := renewalpolicy.CertificateID(der)
		if err != nil {
			return renewalrecord.Observation{}, err
		}
		now := time.Now().UTC()
		return renewalrecord.Observation{CertificateID: cid, Available: true, Information: renewalpolicy.Information{Window: renewalpolicy.Window{Start: now.Add(-10 * time.Second), End: now.Add(-time.Second)}, CheckedAt: now, CheckAfter: now.Add(time.Hour)}}, nil
	}
}

// No runtime acceleration or clock override. Only this test-created job's
// runtime spacing is advanced; all real model/writer clocks remain current.
func manualRenewalJob(t *testing.T, g *gate, cookie *http.Cookie, s session, p inventorystore.RenewalCycle) *renewalJob {
	t.Helper()
	defer clear(s.dataKey[:])
	ctx, cancel := context.WithCancel(context.Background())
	now := g.now().UTC()
	j := &renewalJob{owner: watchOwner(cookie.Value), revision: s.revision, id: strings.Repeat("ab", 16), fp: p.Fingerprint, name: p.Name, zone: p.Zone, domains: p.Domains, config: p.ConfigGeneration, generation: p.Generation, initial: p.Generation, bytesLeft: inventorystore.RenewalCycleBytes, previousBytes: p.BytesLeft, state: "waiting", reason: "ready", started: now, last: now, expires: s.expires, born: time.Now(), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	g.mu.Lock()
	g.renewal = j
	g.mu.Unlock()
	t.Cleanup(func() { cancel(); close(j.done) })
	return j
}
func advanceRenewalJob(t *testing.T, g *gate, j *renewalJob) renewalJobSummary {
	t.Helper()
	g.mu.Lock()
	j.next = time.Time{}
	j.issued = time.Now().Add(-time.Hour)
	g.directoryLast = time.Time{}
	g.mu.Unlock()
	g.tickRenewalJob(j)
	return g.renewalSnapshot(j.owner)
}

func TestLinuxSessionRenewalRealTransactionsRejectUnpinnedReceiptWithoutReplay(t *testing.T) {
	g, cookie, store, fp, s, p := renewalJobFixture(t)
	defer clear(s.dataKey[:])
	g.timingConnect = pastARI(t)
	image, _ := os.ReadFile(store)
	records, _, err := inventorystore.Open(s.dataKey[:], s.installationID[:], image)
	if err != nil {
		t.Fatal(err)
	}
	oldDER := records[0].DER
	orderCalls, creates, borrowed, validates, reads, finalizes, certReads := 0, 0, 0, 0, 0, 0, 0
	info := apiDNS()
	info.URL = acmeorder.Origin + "/acme/order/1234/9876"
	g.orderConnect = func(_ context.Context, permit func() bool, _ crypto.Signer, _ string, order string, names []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		orderCalls++
		if !permit() || order != "" || len(names) != 2 {
			t.Error("wrong new-order scope")
		}
		if err := checkpoint(info.URL); err != nil {
			return acmeorder.Instructions{}, err
		}
		return info, nil
	}
	g.dnsConnect = func(_ context.Context, permit func() bool, _ []byte, scope dnsrecord.Scope, _ dnsrecord.State, cleanup, readOnly bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		if !permit() || cleanup || readOnly || scope.ZoneName != "example.com" {
			t.Error("wrong DNS grant")
		}
		if creates == 0 {
			creates++
			if err := checkpoint(dnsrecord.State{State: "creating"}); err != nil {
				return dnsrecord.State{}, err
			}
			return dnsrecord.State{State: "created", ID: strings.Repeat("b", 32)}, nil
		}
		borrowed++
		return dnsrecord.State{State: "borrowed"}, nil
	}
	g.validationConnect = func(_ context.Context, permit func() bool, _ crypto.Signer, _ string, i acmeorder.Instructions, names []string, readOnly bool) (acmeorder.Validation, error) {
		if !permit() || i.URL != info.URL || len(names) != 2 {
			t.Error("wrong validation scope")
		}
		if !readOnly {
			validates++
			return acmeorder.Validation{URL: info.URL, Expires: info.Expires, OrderStatus: "pending", Statuses: []string{"pending", "pending"}}, nil
		}
		reads++
		return acmeorder.Validation{URL: info.URL, Expires: info.Expires, OrderStatus: "ready", Statuses: []string{"valid", "valid"}}, nil
	}
	g.certificateConnect = func(_ context.Context, permit func() bool, _ crypto.Signer, _, order, _ string, _ []string, _, _ []byte, readOnly bool) (acmestaging.CertificateObservation, error) {
		if !permit() || order != info.URL {
			t.Error("wrong certificate scope")
		}
		if !readOnly {
			finalizes++
			return acmestaging.CertificateObservation{State: "processing", Expires: info.Expires}, nil
		}
		certReads++
		return acmestaging.CertificateObservation{DER: [][]byte{oldDER}}, nil
	}
	j := manualRenewalJob(t, g, cookie, s, p)
	for _, phase := range []string{"timing", "order", "dns-plan", "dns-add", "dns-add", "ack", "validate", "validation-read", "key", "certificate", "certificate-read"} {
		out := advanceRenewalJob(t, g, j)
		if out.Phase != phase {
			t.Fatalf("expected %s, got %+v", phase, out)
		}
		if phase != "certificate-read" && out.State != "waiting" {
			t.Fatalf("step failed %+v", out)
		}
	}
	out := g.renewalSnapshot(j.owner)
	if out.State != "paused" || out.Reason != "outcome-unconfirmed" || out.Saved != "" || orderCalls != 1 || creates != 1 || borrowed != 1 || validates != 1 || reads != 1 || finalizes != 1 || certReads != 1 {
		t.Fatal("lost receipt replay/false completion", out, orderCalls, creates, validates, finalizes)
	}
	g.tickRenewalJob(j)
	if orderCalls != 1 || creates != 1 || validates != 1 || finalizes != 1 || certReads != 1 {
		t.Fatal("paused job replayed I/O")
	}
	image, _ = os.ReadFile(store)
	saved, _, err := inventorystore.Open(s.dataKey[:], s.installationID[:], image)
	if err != nil || len(saved) != 1 || saved[0].Fingerprint != fp {
		t.Fatal("untrusted receipt replaced original", err)
	}
}

func TestLinuxSessionRenewalFreshGrantIntentAndLogoutCancel(t *testing.T) {
	g, cookie, store, fp, s, _ := renewalJobFixture(t)
	defer clear(s.dataKey[:])
	before, _ := os.ReadFile(store)
	if w := renewalCall(g, "preview", renewalJobBody(fp, 15, "preview"), cookie); w.Code != 200 || g.renewal != nil {
		t.Fatal("preview authority", w.Code)
	}
	after, _ := os.ReadFile(store)
	if !bytes.Equal(before, after) {
		t.Fatal("preview wrote store")
	}
	if w := renewalCall(g, "start", strings.Replace(renewalJobBody(fp, 15, "start"), nextTestPassword, "wrong-secret-sentinel", 1), cookie); w.Code != 401 || g.renewal != nil {
		t.Fatal("wrong password granted job", w.Code)
	}
	entered := make(chan struct{})
	released := make(chan struct{})
	defer close(released)
	g.timingConnect = func(ctx context.Context, permit func() bool, _ []byte) (renewalrecord.Observation, error) {
		image, _ := os.ReadFile(store)
		p, _, err := inventorystore.ReadStagingRenewalTiming(s.dataKey[:], s.installationID[:], image, 16, fp)
		if err != nil || !p.Pending || !permit() {
			t.Error("I/O before exact durable intent", err)
		}
		close(entered)
		select {
		case <-ctx.Done():
		case <-released:
		}
		return renewalrecord.Observation{}, errors.New("private-provider-sentinel")
	}
	w := renewalCall(g, "start", renewalJobBody(fp, 15, "start"), cookie)
	if w.Code != 200 {
		t.Fatal("valid grant refused", w.Code)
	}
	select {
	case <-entered:
	case <-time.After(20 * time.Second):
		t.Fatal("job did not reach bounded callback")
	}
	g.mu.Lock()
	j := g.renewal
	g.mu.Unlock()
	if w := watchCall(g, "start", watchBody(fp, 16, "start"), cookie); w.Code != 503 && w.Code != 409 {
		t.Fatal("competing watch", w.Code)
	}
	call(g, "DELETE", "/api/session", "", cookie)
	select {
	case <-j.done:
	case <-time.After(20 * time.Second):
		t.Fatal("logout did not cancel")
	}
	g.mu.Lock()
	out := summarizeRenewal(j)
	g.mu.Unlock()
	if out.State != "paused" || activeRenewal(j) {
		t.Fatal("logout kept authority", out)
	}
	image, _ := os.ReadFile(store)
	p, gen, err := inventorystore.ReadStagingRenewalTiming(s.dataKey[:], s.installationID[:], image, 16, fp)
	if err != nil || gen != 16 || !p.Pending {
		t.Fatal("cancel invented result", err)
	}
	for _, secret := range []string{nextTestPassword, "private-provider-sentinel", "private_key", "token"} {
		raw, _ := json.Marshal(out)
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("job leaked a secret")
		}
	}
}

func TestLinuxSessionRenewalRechecksOriginalSessionScopeAndGeneration(t *testing.T) {
	g, cookie, _, _, s, p := renewalJobFixture(t)
	defer clear(s.dataKey[:])
	calls := 0
	g.timingConnect = func(context.Context, func() bool, []byte) (renewalrecord.Observation, error) {
		calls++
		return renewalrecord.Observation{}, errors.New("must not run")
	}
	for _, mode := range []string{"expired", "revision", "runtime-cap", "missing", "setup", "unready", "config", "generation"} {
		t.Run(mode, func(t *testing.T) {
			j := manualRenewalJob(t, g, cookie, s, p)
			g.mu.Lock()
			g.sessions[j.owner] = s
			switch mode {
			case "expired":
				cs := s
				cs.expires = time.Now().Add(-time.Second)
				g.sessions[j.owner] = cs
				j.expires = cs.expires
			case "revision":
				j.revision[0] ^= 1
			case "runtime-cap":
				j.born = time.Now().Add(-13 * time.Hour)
			case "missing":
				delete(g.sessions, j.owner)
			case "setup":
				cs := s
				cs.setup = true
				g.sessions[j.owner] = cs
			case "unready":
				cs := s
				cs.inventoryReady = false
				g.sessions[j.owner] = cs
			case "config":
				j.config++
			case "generation":
				j.generation++
			}
			g.mu.Unlock()
			g.tickRenewalJob(j)
			out := g.renewalSnapshot(j.owner)
			if out.State != "paused" || j.ctx.Err() == nil || calls != 0 {
				t.Fatal("changed scope retained authority", mode, out, calls)
			}
			g.mu.Lock()
			g.sessions[j.owner] = s
			g.mu.Unlock()
		})
	}
}
