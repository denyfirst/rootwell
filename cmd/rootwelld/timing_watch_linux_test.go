//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/renewalpolicy"
	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

func awaitWatch(t *testing.T, g *gate, condition func(watchSummary) bool) watchSummary {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		value := summarizeWatch(g.watch)
		g.mu.Unlock()
		if condition(value) {
			return value
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("watch did not reach bounded expected state")
	return watchSummary{}
}
func awaitWatchDone(t *testing.T, w *timingWatch) {
	t.Helper()
	select {
	case <-w.done:
	case <-time.After(20 * time.Second):
		t.Fatal("watch did not stop")
	}
}
func TestLinuxTimingWatchSeparateConsentIntentAndStopWithoutSecret(t *testing.T) {
	g, cookie, store, fp, s := timingAPIFixture(t)
	defer clear(s.dataKey[:])
	before, _ := os.ReadFile(store)
	var out watchOutput
	w := watchCall(g, "preview", watchBody(fp, 13, "preview"), cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Readiness == nil || !out.Readiness.CanStart || out.Readiness.Fingerprint != fp || out.AutomaticRenewal || g.watch != nil {
		t.Fatal("preview grants authority or refused valid source", w.Code)
	}
	after, _ := os.ReadFile(store)
	if !bytes.Equal(before, after) {
		t.Fatal("preview wrote state")
	}
	if w := watchCall(g, "start", timingBody(fp, 13, "check"), cookie); w.Code != 400 || g.watch != nil {
		t.Fatal("one-check consent reused as watch")
	}
	if w := watchCall(g, "start", strings.Replace(watchBody(fp, 13, "start"), nextTestPassword, "wrong-password-sentinel", 1), cookie); w.Code != 401 || g.watch != nil {
		t.Fatal("wrong password started watch")
	}
	calls := make(chan struct{}, 2)
	g.timingConnect = func(_ context.Context, permit func() bool, der []byte) (renewalrecord.Observation, error) {
		if !permit() {
			t.Error("legitimate watch permit refused")
		}
		image, _ := os.ReadFile(store)
		intent, gen, err := inventorystore.ReadStagingRenewalTiming(s.dataKey[:], s.installationID[:], image, 14, fp)
		if err != nil || gen != 14 || !intent.Pending {
			t.Error("watch network before durable intent")
		}
		cid, err := renewalpolicy.CertificateID(der)
		if err != nil {
			t.Error("public source unavailable")
		}
		calls <- struct{}{}
		now := time.Now().UTC()
		return renewalrecord.Observation{CertificateID: cid, Available: true, Information: renewalpolicy.Information{Window: renewalpolicy.Window{Start: now.Add(10 * time.Minute), End: now.Add(15 * time.Minute)}, CheckedAt: now, CheckAfter: now.Add(time.Hour)}}, nil
	}
	w = watchCall(g, "start", watchBody(fp, 13, "start"), cookie)
	if w.Code != 200 {
		t.Fatal("valid watch refused", w.Code)
	}
	job := awaitWatch(t, g, func(v watchSummary) bool { return v.Generation == 15 && v.State == "waiting" })
	if len(calls) != 1 || job.Checks != 1 || job.Name == "" || job.Expires != stampWatch(s.expires) || job.NextCheck == "" {
		t.Fatal("watch result/wait/session incorrect", job)
	}
	g.mu.Lock()
	running := g.watch
	g.mu.Unlock()
	if w := watchCall(g, "start", watchBody(fp, 15, "start"), cookie); w.Code != 409 {
		t.Fatal("second watch admitted", w.Code)
	}
	for _, secret := range []string{nextTestPassword, "PRIVATE KEY", "private_key", "acme/order", "token"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("watch output leaked a secret")
		}
	}
	// Stop must remain possible while the crypto/writer path is busy.
	g.derive <- struct{}{}
	w = watchCall(g, "stop", `{"provider":"letsencrypt-staging","watch_id":"`+job.ID+`"}`, cookie)
	<-g.derive
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Watch.State != "paused" || out.Watch.Reason != "stopped" {
		t.Fatal("stop required another secret or write", w.Code)
	}
	awaitWatchDone(t, running)
	image, _ := os.ReadFile(store)
	status, gen, err := inventorystore.ReadStagingRenewalTiming(s.dataKey[:], s.installationID[:], image, 15, fp)
	if err != nil || gen != 15 || status.Pending || len(calls) != 1 {
		t.Fatal("stop replayed or reset saved timing")
	}
	// A new gate has no remembered authority, even with the same saved image.
	fresh, err := newGate(g.accessPath, testWorkbenchAssets(t), localHost)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.watch != nil {
		t.Fatal("restart rehydrated watch authority")
	}
	for _, tc := range []string{"expired", "revision", "generation", "limit", "clock"} {
		t.Run(tc, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			close(done)
			now := time.Now().UTC()
			manual := &timingWatch{owner: watchOwner(cookie.Value), revision: s.revision, id: job.ID, fp: fp, name: job.Name, generation: 15, started: now, last: now, born: time.Now(), expires: s.expires, state: "waiting", reason: "ready", recovery: "none", ctx: ctx, cancel: cancel, done: done}
			g.mu.Lock()
			g.watch = manual
			g.sessions[manual.owner] = s
			switch tc {
			case "expired":
				cs := s
				cs.expires = now.Add(-time.Second)
				manual.expires = cs.expires
				g.sessions[manual.owner] = cs
			case "revision":
				manual.revision[0] ^= 1
			case "generation":
				manual.generation = 14
			case "limit":
				manual.checks = 12
			case "clock":
				manual.last = now.Add(time.Hour)
			}
			g.mu.Unlock()
			g.tickTimingWatch(manual)
			g.mu.Lock()
			state := summarizeWatch(manual)
			g.sessions[manual.owner] = s
			g.mu.Unlock()
			if state.State != "paused" || len(calls) != 1 {
				t.Fatal("ended/stale/limited watch reached provider", tc, state)
			}
		})
	}
}

func TestLinuxTimingWatchRevocationRetainsPendingAndNeverAutoRetires(t *testing.T) {
	for _, mode := range []string{"stop", "logout", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			g, cookie, store, fp, s := timingAPIFixture(t)
			defer clear(s.dataKey[:])
			entered := make(chan struct{})
			g.timingConnect = func(ctx context.Context, permit func() bool, der []byte) (renewalrecord.Observation, error) {
				close(entered)
				<-ctx.Done()
				if permit() {
					t.Error("revoked watch kept authority")
				}
				cid, _ := renewalpolicy.CertificateID(der)
				return renewalrecord.Observation{CertificateID: cid}, nil
			}
			w := watchCall(g, "start", watchBody(fp, 13, "start"), cookie)
			if w.Code != 200 {
				t.Fatal("start refused", w.Code)
			}
			select {
			case <-entered:
			case <-time.After(20 * time.Second):
				t.Fatal("watch did not enter bounded fake provider")
			}
			g.mu.Lock()
			running := g.watch
			id := running.id
			g.mu.Unlock()
			switch mode {
			case "stop":
				if w := watchCall(g, "stop", `{"provider":"letsencrypt-staging","watch_id":"`+id+`"}`, cookie); w.Code != 200 {
					t.Fatal("in-flight stop refused")
				}
			case "logout":
				if w := call(g, "DELETE", "/api/session", "", cookie); w.Code != 204 {
					t.Fatal("logout refused")
				}
			case "shutdown":
				_ = g.Close()
			}
			awaitWatchDone(t, running)
			image, _ := os.ReadFile(store)
			p, err := inventorystore.ReadTimingReadiness(s.dataKey[:], s.installationID[:], image, 14, fp, time.Now().UTC())
			if err != nil || p.Generation != 14 || p.CanStart || !p.Timing.Pending || p.Recovery != "timing" {
				t.Fatal("revocation erased/retired pending result", err)
			}
			if mode == "stop" {
				oldWait := p.Timing.NextCheck
				w = timingCall(g, "interrupt", timingBody(fp, 14, "interrupt"), cookie)
				if w.Code != 200 {
					t.Fatal("explicit local recovery refused", w.Code)
				}
				image, _ = os.ReadFile(store)
				after, err := inventorystore.ReadTimingReadiness(s.dataKey[:], s.installationID[:], image, 15, fp, time.Now().UTC())
				if err != nil || !after.CanStart || after.Reason != "provider-wait" || after.Timing.NextCheck != oldWait {
					t.Fatal("recovery reset wait", err)
				}
			}
		})
	}
}
