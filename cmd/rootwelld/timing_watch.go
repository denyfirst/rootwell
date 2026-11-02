package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

const watchLimit = 12
const watchSpacing = 5 * time.Minute

// No password, data key, signer or credential is retained in a job. Authority
// is only the original ready-session hash/revision/expiry and selected source.
type timingWatch struct {
	owner                        [32]byte
	revision                     [32]byte
	id, fp                       string
	name                         string
	generation                   uint64
	started, last, next, expires time.Time
	born, issued                 time.Time // runtime-only monotonic bounds, never serialized
	checks                       int
	state, reason, recovery      string
	ctx                          context.Context
	cancel                       context.CancelFunc
	done                         chan struct{}
}

type watchSummary struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Generation  uint64 `json:"generation"`
	State       string `json:"state"`
	Reason      string `json:"reason"`
	Recovery    string `json:"recovery"`
	CheckedAt   string `json:"checked_at"`
	NextCheck   string `json:"next_check"`
	Expires     string `json:"expires"`
	Checks      int    `json:"checks"`
	Limit       int    `json:"limit"`
}

func stampWatch(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func summarizeWatch(w *timingWatch) watchSummary {
	if w == nil {
		return watchSummary{State: "not-running", Reason: "not-started", Recovery: "none", Limit: watchLimit}
	}
	return watchSummary{Name: w.name, ID: w.id, Fingerprint: w.fp, Generation: w.generation, State: w.state, Reason: w.reason, Recovery: w.recovery, CheckedAt: stampWatch(w.last), NextCheck: stampWatch(w.next), Expires: stampWatch(w.expires), Checks: w.checks, Limit: watchLimit}
}
func activeWatch(w *timingWatch) bool {
	return w != nil && (w.state == "waiting" || w.state == "running")
}

// Called with g.mu held; cancellation never waits while holding the mutex.
func (g *gate) pauseWatchLocked(w *timingWatch, reason, recovery string) {
	if g.watch != w || w == nil {
		return
	}
	w.state, w.reason, w.recovery, w.next = "paused", reason, recovery, time.Time{}
	w.cancel()
}
func (g *gate) watchSession(w *timingWatch) (session, bool) {
	revision, err := instanceaccess.Revision(g.accessPath)
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[w.owner]
	liveNow := g.now()
	now := liveNow.UTC()
	if !ok || err != nil || g.closed || g.watch != w || !activeWatch(w) || w.ctx.Err() != nil || s.setup || !s.inventoryReady || s.revision != w.revision || revision != w.revision || s.expires != w.expires || now.Before(w.started) || now.Before(w.last) || !liveNow.Before(w.expires) || w.born.IsZero() || time.Since(w.born) < 0 || time.Since(w.born) >= 12*time.Hour {
		clear(s.dataKey[:])
		if activeWatch(w) {
			g.pauseWatchLocked(w, "access-ended", "none")
		}
		return session{}, false
	}
	return s, true
}

func (g *gate) newTimingWatch(owner [32]byte, s session, fp, name string, gen uint64) (*timingWatch, error) {
	defer clear(s.dataKey[:])
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, errors.New("watch unavailable")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	liveNow := g.now()
	now := liveNow.UTC()
	current, ok := g.sessions[owner]
	defer clear(current.dataKey[:])
	if !ok || g.closed || current.setup || !current.inventoryReady || current.revision != s.revision || current.expires != s.expires || !liveNow.Before(s.expires) || s.expires.Sub(liveNow) > 12*time.Hour {
		return nil, errors.New("access ended")
	}
	if g.watch != nil {
		select {
		case <-g.watch.done:
		default:
			return nil, errors.New("watch still active")
		}
	}
	if g.renewal != nil && !finished(g.renewal.done) {
		return nil, errors.New("renewal still active")
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &timingWatch{name: name, owner: owner, revision: s.revision, id: hex.EncodeToString(raw[:]), fp: fp, generation: gen, started: now, last: now, expires: s.expires, state: "waiting", reason: "ready", recovery: "none", ctx: ctx, cancel: cancel, done: make(chan struct{})}
	w.born = time.Now()
	g.watch = w
	go g.runTimingWatch(w)
	return w, nil
}

func (g *gate) runTimingWatch(w *timingWatch) {
	defer close(w.done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		g.tickTimingWatch(w)
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (g *gate) tickTimingWatch(w *timingWatch) {
	s, ok := g.watchSession(w)
	if !ok {
		return
	}
	defer clear(s.dataKey[:])
	g.mu.Lock()
	now := g.now().UTC()
	w.last = now
	if w.checks >= watchLimit {
		g.pauseWatchLocked(w, "check-limit", "timing")
		g.mu.Unlock()
		return
	}
	expected := w.generation
	g.mu.Unlock()
	if !g.startDerivation() {
		g.deferTimingWatch(w, "busy")
		return
	}
	defer func() { <-g.derive }()
	ctx, cancel := context.WithTimeout(w.ctx, 25*time.Second)
	defer cancel()
	permit := func() bool {
		current, valid := g.watchSession(w)
		clear(current.dataKey[:])
		return valid && ctx.Err() == nil
	}
	if !permit() {
		return
	}
	p, err := instanceaccess.ReadTimingReadiness(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, expected, w.fp, time.Now().UTC())
	if err != nil {
		g.failTimingWatch(w, "storage-changed", "readiness")
		return
	}
	if !p.CanStart {
		g.failTimingWatch(w, p.Reason, p.Recovery)
		return
	}
	g.mu.Lock()
	if g.watch != w || !activeWatch(w) {
		g.mu.Unlock()
		return
	}
	if p.NextCheck != "" {
		at, err := time.Parse(time.RFC3339Nano, p.NextCheck)
		if err != nil {
			g.pauseWatchLocked(w, "clock-unavailable", "maintenance")
			g.mu.Unlock()
			return
		}
		if at.After(w.next) {
			w.next = at
		}
	}
	minimumWatchSpacing(w, g.now().UTC())
	if g.now().UTC().Before(w.next) {
		w.state, w.reason = "waiting", "provider-wait"
		g.mu.Unlock()
		return
	}
	g.mu.Unlock()
	if !permit() {
		return
	}
	if !g.startRegistrationProvider(false) {
		g.deferTimingWatch(w, "busy")
		return
	}
	defer func() { g.mu.Lock(); g.directoryBusy = false; g.mu.Unlock() }()
	g.mu.Lock()
	if !activeWatch(w) || g.watch != w || w.ctx.Err() != nil {
		g.mu.Unlock()
		return
	}
	w.state, w.reason = "running", "checking"
	w.next = time.Time{}
	w.checks++
	w.issued = time.Now()
	g.mu.Unlock()
	connect := g.timingConnect
	if connect == nil {
		connect = acmestaging.RenewalInformation
	}
	result, gen, err := instanceaccess.RunStagingRenewalTiming(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, expected, w.fp, permit, func(allowed func() bool, der []byte) (renewalrecord.Observation, error) {
		return connect(ctx, allowed, der)
	})
	if err != nil {
		g.failTimingWatch(w, "outcome-unconfirmed", "readiness")
		return
	}
	if !permit() {
		return
	}
	g.mu.Lock()
	if g.watch != w || !activeWatch(w) || w.ctx.Err() != nil {
		g.mu.Unlock()
		return
	}
	w.generation = gen
	w.last = g.now().UTC()
	// A confirmed failure also needs fresh operator review; there is no automatic
	// retry chain, no automatic retirement and no DNS/account/order mutation.
	if result.State != "ari" && result.State != "unsupported" {
		g.pauseWatchLocked(w, "provider-failed", "timing")
		g.mu.Unlock()
		return
	}
	if w.checks >= watchLimit {
		g.pauseWatchLocked(w, "check-limit", "timing")
		g.mu.Unlock()
		return
	}
	w.state, w.reason = "waiting", "provider-wait"
	w.next = w.last.Add(watchSpacing)
	for _, stamp := range []string{result.NextCheck, result.ProviderNotBefore} {
		if at, e := time.Parse(time.RFC3339Nano, stamp); e == nil && at.After(w.next) {
			w.next = at
		}
	}
	g.mu.Unlock()
}

func (g *gate) failTimingWatch(w *timingWatch, reason, recovery string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if activeWatch(w) {
		g.pauseWatchLocked(w, reason, recovery)
	}
}
func (g *gate) deferTimingWatch(w *timingWatch, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.watch == w && activeWatch(w) {
		w.state, w.reason = "waiting", reason
		if next := g.now().UTC().Add(time.Minute); next.After(w.next) {
			w.next = next
		}
	}
}

func watchOwner(token string) [32]byte { return sha256.Sum256([]byte(token)) }

// Runtime-only elapsed time prevents a wall-clock jump or a busy tick from
// shortening the minimum gap. Called under g.mu before a provider slot.
func minimumWatchSpacing(w *timingWatch, wall time.Time) {
	if !w.issued.IsZero() {
		if remaining := watchSpacing - time.Since(w.issued); remaining > 0 {
			if earliest := wall.Add(remaining); earliest.After(w.next) {
				w.next = earliest
			}
		}
	}
}
