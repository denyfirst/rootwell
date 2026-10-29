package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

const renewalActionLimit = 160

// Only runtime/public scope. No session value, unlock, signer, token, inventory
// image, CSR, callback or provider URL may be retained here.
type renewalJob struct {
	owner, revision                          [32]byte
	id, fp, name, zone                       string
	domains                                  []string
	config, generation, initial              uint64
	bytesLeft, previousBytes                 int
	actions, timing, validation, certificate int
	state, reason, phase, saved              string
	started, last, next, expires             time.Time
	born, issued                             time.Time
	ctx                                      context.Context
	cancel                                   context.CancelFunc
	done                                     chan struct{}
}

type renewalJobSummary struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	Generation  uint64 `json:"generation"`
	State       string `json:"state"`
	Reason      string `json:"reason"`
	Phase       string `json:"phase"`
	Saved       string `json:"saved_fingerprint"`
	CheckedAt   string `json:"checked_at"`
	Next        string `json:"next_check"`
	Expires     string `json:"expires"`
	Actions     int    `json:"actions"`
	Limit       int    `json:"limit"`
}

func activeRenewal(j *renewalJob) bool {
	return j != nil && (j.state == "waiting" || j.state == "running")
}
func summarizeRenewal(j *renewalJob) renewalJobSummary {
	if j == nil {
		return renewalJobSummary{State: "not-running", Reason: "not-started", Limit: renewalActionLimit}
	}
	return renewalJobSummary{ID: j.id, Fingerprint: j.fp, Name: j.name, Generation: j.generation, State: j.state, Reason: j.reason, Phase: j.phase, Saved: j.saved, CheckedAt: stampWatch(j.last), Next: stampWatch(j.next), Expires: stampWatch(j.expires), Actions: j.actions, Limit: renewalActionLimit}
}

// g.mu held. Never wait for a worker under this lock.
func (g *gate) pauseRenewalLocked(j *renewalJob, reason string) {
	if j == nil || g.renewal != j || j.state == "complete" {
		return
	}
	j.state, j.reason, j.next = "paused", reason, time.Time{}
	j.cancel()
}

func (g *gate) renewalSession(j *renewalJob) (session, bool) {
	rev, err := instanceaccess.Revision(g.accessPath)
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[j.owner]
	now := g.now()
	if !ok || err != nil || g.closed || g.renewal != j || !activeRenewal(j) || j.ctx.Err() != nil || s.setup || !s.inventoryReady || s.revision != j.revision || rev != j.revision || s.expires != j.expires || now.Before(j.started) || now.Before(j.last) || !now.Before(j.expires) || j.born.IsZero() || time.Since(j.born) < 0 || time.Since(j.born) >= 12*time.Hour {
		clear(s.dataKey[:])
		if activeRenewal(j) {
			g.pauseRenewalLocked(j, "access-ended")
		}
		return session{}, false
	}
	return s, true
}

func finished(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func (g *gate) newRenewalJob(owner [32]byte, s session, p inventorystore.RenewalCycle) (*renewalJob, error) {
	defer clear(s.dataKey[:])
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, errors.New("renewal unavailable")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	current, ok := g.sessions[owner]
	defer clear(current.dataKey[:])
	if !ok || g.closed || current.setup || !current.inventoryReady || current.revision != s.revision || current.expires != s.expires || !now.Before(s.expires) || s.expires.Sub(now) > 12*time.Hour {
		return nil, errors.New("access ended")
	}
	if g.watch != nil && !finished(g.watch.done) || g.renewal != nil && !finished(g.renewal.done) {
		return nil, errors.New("another watch or renewal is finishing")
	}
	decision := inventorystore.DecideRenewalCycle(p, inventorystore.RenewalCycleEvents, inventorystore.RenewalCycleBytes, time.Now().UTC())
	if decision.Action == "pause" || decision.Action == "complete" {
		return nil, errors.New("renewal not ready")
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &renewalJob{owner: owner, revision: s.revision, id: hex.EncodeToString(raw[:]), fp: p.Fingerprint, name: p.Name, zone: p.Zone, domains: slices.Clone(p.Domains), config: p.ConfigGeneration, generation: p.Generation, initial: p.Generation, bytesLeft: inventorystore.RenewalCycleBytes, previousBytes: p.BytesLeft, state: "waiting", reason: "ready", started: now.UTC(), last: now.UTC(), expires: s.expires, born: time.Now(), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	g.renewal = j
	go g.runRenewalJob(j)
	return j, nil
}

func (g *gate) runRenewalJob(j *renewalJob) {
	defer close(j.done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		g.tickRenewalJob(j)
		select {
		case <-j.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (g *gate) failRenewal(j *renewalJob, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if activeRenewal(j) {
		g.pauseRenewalLocked(j, reason)
	}
}

func (g *gate) tickRenewalJob(j *renewalJob) {
	s, ok := g.renewalSession(j)
	if !ok {
		return
	}
	defer clear(s.dataKey[:])
	g.mu.Lock()
	now := g.now().UTC()
	j.last = now
	if j.actions >= renewalActionLimit || j.generation < j.initial || j.generation-j.initial >= inventorystore.RenewalCycleEvents {
		g.pauseRenewalLocked(j, "action-limit")
		g.mu.Unlock()
		return
	}
	if !j.issued.IsZero() {
		if remaining := time.Minute - time.Since(j.issued); remaining > 0 {
			j.next = maxJobTime(j.next, now.Add(remaining))
		}
	}
	if now.Before(j.next) {
		j.state = "waiting"
		g.mu.Unlock()
		return
	}
	expected := j.generation
	g.mu.Unlock()
	if !g.startDerivation() {
		g.deferRenewal(j)
		return
	}
	defer func() { <-g.derive }()
	ctx, cancel := context.WithTimeout(j.ctx, 25*time.Second)
	defer cancel()
	permit := func() bool {
		current, live := g.renewalSession(j)
		clear(current.dataKey[:])
		return live && ctx.Err() == nil
	}
	if !permit() {
		return
	}
	p, err := instanceaccess.ReadRenewalCycle(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, expected, j.fp)
	if err != nil {
		g.failRenewal(j, "storage-changed")
		return
	}
	if p.ConfigGeneration != j.config || p.Zone != j.zone || !slices.Equal(p.Domains, j.domains) {
		g.failRenewal(j, "scope-changed")
		return
	}
	g.mu.Lock()
	if g.renewal != j || !activeRenewal(j) || j.ctx.Err() != nil {
		g.mu.Unlock()
		return
	}
	j.bytesLeft -= max(0, j.previousBytes-p.BytesLeft)
	j.previousBytes = p.BytesLeft
	j.saved = ""
	if p.OrderSource == j.fp {
		j.saved = p.SavedFingerprint
	}
	used := j.generation - j.initial
	if j.generation < j.initial || used >= inventorystore.RenewalCycleEvents {
		g.pauseRenewalLocked(j, "action-limit")
		g.mu.Unlock()
		return
	}
	remaining := inventorystore.RenewalCycleEvents - int(used)
	d := inventorystore.DecideRenewalCycle(p, remaining, j.bytesLeft, time.Now().UTC())
	j.phase, j.reason = d.Action, d.Reason
	if d.Action == "pause" {
		g.pauseRenewalLocked(j, d.Reason)
		g.mu.Unlock()
		return
	}
	if d.Action == "complete" {
		j.state, j.reason, j.next = "complete", "complete", time.Time{}
		j.cancel()
		g.mu.Unlock()
		return
	}
	if d.Action == "wait" {
		next, e := time.Parse(time.RFC3339Nano, d.Next)
		if e != nil {
			g.pauseRenewalLocked(j, "clock-unavailable")
		} else {
			j.state, j.next = "waiting", next
		}
		g.mu.Unlock()
		return
	}
	limited := d.Action == "timing" && j.timing >= 12 || d.Action == "validation-read" && j.validation >= 12 || d.Action == "certificate-read" && j.certificate >= 12
	if limited {
		g.pauseRenewalLocked(j, "poll-limit")
		g.mu.Unlock()
		return
	}
	g.mu.Unlock()
	if !permit() {
		return
	}
	if renewalNetworkAction(d.Action) {
		if !g.startRegistrationProvider(false) {
			g.deferRenewal(j)
			return
		}
		defer func() { g.mu.Lock(); g.directoryBusy = false; g.mu.Unlock() }()
	}
	g.mu.Lock()
	if !activeRenewal(j) || g.renewal != j || j.ctx.Err() != nil {
		g.mu.Unlock()
		return
	}
	j.state, j.reason, j.next = "running", d.Action, time.Time{}
	j.actions++
	j.issued = time.Now()
	switch d.Action {
	case "timing":
		j.timing++
	case "validation-read":
		j.validation++
	case "certificate-read":
		j.certificate++
	}
	g.mu.Unlock()
	gen, err := g.executeRenewalAction(ctx, s, expected, j.fp, d, permit)
	if err != nil {
		g.failRenewal(j, "outcome-unconfirmed")
		return
	}
	if !permit() {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.renewal != j || !activeRenewal(j) || j.ctx.Err() != nil {
		return
	}
	if gen < expected || gen-expected > 3 || gen-j.initial >= inventorystore.RenewalCycleEvents {
		g.pauseRenewalLocked(j, "outcome-unconfirmed")
		return
	}
	j.generation, j.last, j.state, j.reason = gen, g.now().UTC(), "waiting", "step-saved"
	gap := time.Minute
	if d.Action == "validate" || d.Action == "validation-read" || d.Action == "certificate" || d.Action == "certificate-read" || d.Action == "timing" {
		gap = 5 * time.Minute
	}
	j.next = j.last.Add(gap)
	// Keep this longer runtime floor separately from later wall-clock ticks.
	j.issued = time.Now().Add(gap - time.Minute)
}

func maxJobTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
func renewalNetworkAction(action string) bool {
	switch action {
	case "timing", "order", "order-read", "validate", "validation-read", "certificate", "certificate-read", "dns-add", "dns-check", "dns-cleanup":
		return true
	}
	return false
}
func (g *gate) deferRenewal(j *renewalJob) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.renewal == j && activeRenewal(j) {
		j.state, j.reason = "waiting", "busy"
		j.next = maxJobTime(j.next, g.now().UTC().Add(time.Minute))
	}
}
