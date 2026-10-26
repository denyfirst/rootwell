package inventorystore

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/denyfirst/rootwell/internal/providerretry"
	"github.com/denyfirst/rootwell/internal/renewalpolicy"
	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

func lookupTiming(key, id []byte, m manifest, fp string) (timingPayload, bool, error) {
	for _, item := range m.RenewalTimings {
		p, err := openTimingPayload(key, id, m, item)
		if err != nil {
			return timingPayload{}, false, err
		}
		if p.Fingerprint == fp {
			return p, true, nil
		}
	}
	return timingPayload{}, false, nil
}

// The returned image MUST commit under the same private writer lock before
// Execute can receive the lease. Status itself grants no provider authority.
func BeginStagingRenewalTiming(key, id, image []byte, expected uint64, fp string) ([]byte, *RenewalTimingAttempt, RenewalTimingStatus, uint64, error) {
	bad := func(err error) ([]byte, *RenewalTimingAttempt, RenewalTimingStatus, uint64, error) {
		return nil, nil, RenewalTimingStatus{}, 0, err
	}
	next, attempt, gen, err := beginTimingAt(key, id, image, expected, fp, time.Now().UTC())
	if err != nil {
		return bad(err)
	}
	finished := time.Now().UTC()
	status, g, err := readTimingStatusAt(key, id, next, gen, fp, finished)
	if err != nil {
		return bad(err)
	}
	if time.Now().UTC().Before(finished) || !time.Now().UTC().Before(attempt.lease.until) {
		return bad(ErrInvalid)
	}
	return next, attempt, status, g, nil
}

// Only internal functions/tests may supply a clock. No runtime date override.
func beginTimingAt(key, id, image []byte, expected uint64, fp string, at time.Time) ([]byte, *RenewalTimingAttempt, uint64, error) {
	bad := func(err error) ([]byte, *RenewalTimingAttempt, uint64, error) { return nil, nil, 0, err }
	status, gen, err := readTimingStatusAt(key, id, image, expected, fp, at)
	if err != nil {
		return bad(err)
	}
	if status.Expired || status.Superseded {
		return bad(ErrInvalid)
	}
	if status.Blocked {
		return bad(ErrTimingBlocked)
	}
	if !status.CanRead {
		return bad(ErrTimingWait)
	}
	m, records, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	r, life, err := timingSource(records, fp)
	if err != nil {
		return bad(err)
	}
	p, exists, err := lookupTiming(key, id, m, fp)
	if err != nil {
		return bad(err)
	}
	if !exists {
		if len(m.RenewalTimings) >= maxRecords {
			return bad(ErrLimit)
		}
		id, err := renewalpolicy.CertificateID(r.DER)
		if err != nil {
			return bad(ErrInvalid)
		}
		choice, err := renewalpolicy.Select(life, nil, at, time.Time{})
		if err != nil {
			return bad(ErrInvalid)
		}
		p = timingPayload{Fingerprint: fp, CertificateID: id, PreparedAt: timingStamp(at), PreparedGeneration: gen + 1, FallbackAt: timingStamp(choice.At), Source: "fallback", RenewAt: timingStamp(choice.At)}
	}
	p.Pending, p.Outcome, p.OutcomeAt = true, "pending", ""
	p.Failures = min(6, p.Failures+1)
	p.StartedAt = timingStamp(at)
	nextCheck, err := renewalpolicy.ErrorCheckAt(at, false, p.Failures)
	if err != nil {
		return bad(ErrInvalid)
	}
	p.NextCheck = timingStamp(nextCheck)
	next, g, err := sealTimingPlan(key, id, m, p, "acme-timing-read-started", providerretry.Hint{}, at)
	if err != nil {
		return bad(err)
	}
	l := &timingLease{image: sha256.Sum256(next), generation: g, fingerprint: fp, started: at, until: at.Add(20 * time.Second)}
	return next, &RenewalTimingAttempt{lease: l}, g, nil
}

func ExecuteStagingRenewalTiming(key, id, image []byte, attempt *RenewalTimingAttempt, permit func() bool, use RenewalTimingOperation) ([]byte, RenewalTimingStatus, uint64, error) {
	next, gen, err := executeTimingAt(key, id, image, attempt, permit, use, time.Now)
	if err != nil {
		return nil, RenewalTimingStatus{}, 0, err
	}
	finished := time.Now().UTC()
	status, g, err := readTimingStatusAt(key, id, next, gen, attempt.lease.fingerprint, finished)
	if err != nil || permit == nil || !permit() || time.Now().UTC().Before(finished) || !time.Now().UTC().Before(attempt.lease.until) {
		return nil, RenewalTimingStatus{}, 0, ErrInvalid
	}
	return next, status, g, nil
}

func executeTimingAt(key, id, image []byte, attempt *RenewalTimingAttempt, permit func() bool, use RenewalTimingOperation, clock func() time.Time) ([]byte, uint64, error) {
	bad := func(err error) ([]byte, uint64, error) { return nil, 0, err }
	if attempt == nil || attempt.lease == nil || !attempt.lease.used.CompareAndSwap(false, true) {
		return bad(ErrInvalid)
	}
	l := attempt.lease
	if l.image != sha256.Sum256(image) {
		return bad(ErrStaleGeneration)
	}
	m, records, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	if m.Generation != l.generation || permit == nil || use == nil || clock == nil {
		return bad(ErrInvalid)
	}
	p, exists, err := lookupTiming(key, id, m, l.fingerprint)
	if err != nil || !exists || !p.Pending {
		return bad(ErrInvalid)
	}
	r, life, err := timingSource(records, l.fingerprint)
	if err != nil {
		return bad(err)
	}
	superseded, err := completedRenewalSources(key, id, m)
	if err != nil || superseded[l.fingerprint] {
		return bad(ErrInvalid)
	}
	started, _ := timingTime(p.StartedAt)
	allowed := func() bool {
		now := clock().UTC()
		return permit() && !now.Before(started) && now.Before(l.until) && now.Before(life.End)
	}
	wait, err := openStagingWait(key, id, m)
	if err != nil || !stagingWaitReady(wait, clock().UTC()) || !timingClock(key, id, m, clock().UTC(), &p) || !allowed() {
		return bad(ErrInvalid)
	}
	public := bytes.Clone(r.DER)
	defer clear(public)
	observed, callErr := use(allowed, public)
	if !allowed() {
		return bad(ErrInvalid)
	}
	now := clock().UTC()
	p.Pending, p.OutcomeAt = false, timingStamp(now)
	if callErr != nil {
		if observed != (renewalrecord.Observation{}) {
			return bad(ErrInvalid)
		}
		temporary := false
		hint := providerretry.Hint{}
		var failure *renewalrecord.Failure
		if errors.As(callErr, &failure) && failure != nil {
			temporary, hint = failure.Temporary, failure.Hint
		}
		next, err := renewalpolicy.ErrorCheckAt(now, temporary, p.Failures)
		if err != nil {
			return bad(ErrInvalid)
		}
		p.Outcome, p.NextCheck = "error", timingStamp(next)
		image, g, err := sealTimingPlan(key, id, m, p, "acme-timing-wait-saved", hint, now)
		if err != nil {
			return bad(err)
		}
		if !allowed() {
			return bad(ErrInvalid)
		}
		return image, g, nil
	}
	if observed.CertificateID != p.CertificateID {
		return bad(ErrInvalid)
	}
	if !observed.Available {
		if observed.Information != (renewalpolicy.Information{}) {
			return bad(ErrInvalid)
		}
		p.Outcome, p.Failures = "unsupported", 0
		p.NextCheck = timingStamp(now.Add(24 * time.Hour))
	} else {
		i := observed.Information
		if i.CheckedAt.Before(started) || i.CheckedAt.After(now) {
			return bad(ErrInvalid)
		}
		window := &timingWindow{Start: timingStamp(i.Window.Start), End: timingStamp(i.Window.End), CheckedAt: timingStamp(i.CheckedAt), CheckAfter: timingStamp(i.CheckAfter)}
		// Validate every response, but draw entropy only for a new window. A
		// restart/status/same-window refresh cannot silently postpone the choice.
		if p.ARI == nil || p.ARI.Start != window.Start || p.ARI.End != window.End {
			selected, err := renewalpolicy.Select(life, &i, now, time.Time{})
			if err != nil {
				return bad(ErrInvalid)
			}
			old, _ := timingTime(p.RenewAt)
			if p.Source == "fallback" || selected.At.Before(old) {
				p.Source, p.RenewAt = "ari", timingStamp(selected.At)
				p.Choice = &timingChoice{Start: window.Start, End: window.End, ComputedAt: timingStamp(now)}
			}
		} else {
			// No random selection here; repeat the pure interval/freshness checks.
			if !i.Window.End.After(i.Window.Start) || i.Window.End.After(life.End) || !now.Before(i.CheckAfter) || i.CheckAfter.Sub(i.CheckedAt) < time.Minute || i.CheckAfter.Sub(i.CheckedAt) > 24*time.Hour {
				return bad(ErrInvalid)
			}
		}
		p.ARI, p.Outcome, p.Failures, p.NextCheck = window, "ari", 0, timingStamp(i.CheckAfter)
	}
	next, g, err := sealTimingPlan(key, id, m, p, "acme-timing-observed", providerretry.Hint{}, now)
	if err != nil {
		return bad(err)
	}
	if !allowed() {
		return bad(ErrInvalid)
	}
	return next, g, nil
}

// Interrupt only retires a local GET intent, preserving its count/wait and
// global provider barrier. It cannot cancel/revoke a CA order or abandon DNS.
func InterruptStagingRenewalTiming(key, id, image []byte, expected uint64, fp string) ([]byte, RenewalTimingStatus, uint64, error) {
	next, g, err := interruptTimingAt(key, id, image, expected, fp, time.Now().UTC())
	if err != nil {
		return nil, RenewalTimingStatus{}, 0, err
	}
	finished := time.Now().UTC()
	s, gen, err := readTimingStatusAt(key, id, next, g, fp, finished)
	if err != nil {
		return nil, RenewalTimingStatus{}, 0, err
	}
	if time.Now().UTC().Before(finished) {
		return nil, RenewalTimingStatus{}, 0, ErrInvalid
	}
	return next, s, gen, nil
}
func interruptTimingAt(key, id, image []byte, expected uint64, fp string, at time.Time) ([]byte, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, 0, ErrStaleGeneration
	}
	p, exists, err := lookupTiming(key, id, m, fp)
	if err != nil || !exists || !p.Pending || !timingClock(key, id, m, at, &p) {
		return nil, 0, ErrInvalid
	}
	p.Pending, p.Outcome, p.OutcomeAt = false, "interrupted", timingStamp(at)
	return sealTimingPlan(key, id, m, p, "acme-timing-interrupted", providerretry.Hint{}, at)
}
