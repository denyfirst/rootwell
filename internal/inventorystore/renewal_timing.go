package inventorystore

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"sync/atomic"
	"time"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/providerretry"
	"github.com/denyfirst/rootwell/internal/publicinventory"
	"github.com/denyfirst/rootwell/internal/renewalpolicy"
	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

const timingPlainLimit = 2048
const timingOutcomeBytes = 8 << 10

var ErrTimingWait = errors.New("renewal timing check is waiting")
var ErrTimingBlocked = errors.New("renewal timing check needs reviewed maintenance")

type timingWindow struct {
	Start      string `json:"start"`
	End        string `json:"end"`
	CheckedAt  string `json:"checked_at"`
	CheckAfter string `json:"check_after"`
}
type timingChoice struct {
	Start      string `json:"start"`
	End        string `json:"end"`
	ComputedAt string `json:"computed_at"`
}
type timingPayload struct {
	Fingerprint        string        `json:"fingerprint"`
	CertificateID      string        `json:"certificate_id"`
	PreparedAt         string        `json:"prepared_at"`
	PreparedGeneration uint64        `json:"prepared_generation"`
	FallbackAt         string        `json:"fallback_at"`
	Source             string        `json:"source"`
	RenewAt            string        `json:"renew_at"`
	Choice             *timingChoice `json:"choice,omitempty"`
	ARI                *timingWindow `json:"ari,omitempty"`
	Pending            bool          `json:"pending"`
	StartedAt          string        `json:"started_at"`
	Outcome            string        `json:"outcome"`
	OutcomeAt          string        `json:"outcome_at"`
	Failures           int           `json:"failures"`
	NextCheck          string        `json:"next_check"`
}

// Public metadata only. EffectiveAt may fall back to the already saved local
// choice when ARI is stale/unavailable; provider waits always win. No authority.
type RenewalTimingStatus struct {
	Fingerprint       string `json:"fingerprint"`
	Prepared          bool   `json:"prepared"`
	State             string `json:"state"`
	StartedAt         string `json:"started_at"`
	ObservedAt        string `json:"observed_at"`
	Pending           bool   `json:"pending"`
	CanRead           bool   `json:"can_read"`
	CanInterrupt      bool   `json:"can_interrupt"`
	Source            string `json:"source"`
	RenewAt           string `json:"renew_at"`
	FallbackAt        string `json:"fallback_at"`
	EffectiveAt       string `json:"effective_at"`
	NextCheck         string `json:"next_check"`
	ProviderNotBefore string `json:"provider_not_before"`
	Blocked           bool   `json:"blocked"`
	Failures          int    `json:"failures"`
	WindowStart       string `json:"window_start"`
	WindowEnd         string `json:"window_end"`
	CheckedAt         string `json:"checked_at"`
	Expired           bool   `json:"expired"`
	Superseded        bool   `json:"superseded"`
}

type RenewalTimingAttempt struct{ lease *timingLease }
type timingLease struct {
	used        atomic.Bool
	image       [32]byte
	generation  uint64
	fingerprint string
	started     time.Time
	until       time.Time
}

// Callback receives only a detached public certificate, not any signer/key/
// token/URI. A future reviewed pinned connector must establish the source.
type RenewalTimingOperation func(func() bool, []byte) (renewalrecord.Observation, error)

func timingStamp(at time.Time) string { return at.UTC().Format(time.RFC3339Nano) }
func timingTime(value string) (time.Time, bool) {
	at, err := time.Parse(time.RFC3339Nano, value)
	return at, err == nil && at.Year() >= 2020 && at.Year() <= 2100 && timingStamp(at) == value
}
func timingRecordID(fp string) []byte {
	sum := sha256.Sum256([]byte("rootwell.acme-renewal-timing.v1:" + fp))
	return sum[:]
}
func timingKey(key, id []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, id, "rootwell.acme-renewal-timing-key.v1", 32)
}

func openTimingPayload(key, id []byte, m manifest, item sealedRecord) (timingPayload, error) {
	bad := func() (timingPayload, error) { return timingPayload{}, ErrInvalid }
	if len(item.ID) != 32 || item.Generation < 2 || item.Generation > m.Generation || len(item.Ciphertext) > timingPlainLimit+64 {
		return bad()
	}
	k, err := timingKey(key, id)
	if err != nil {
		return bad()
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	defer clear(plain)
	var p timingPayload
	if err != nil || len(plain) > timingPlainLimit || !strictJSON(plain, &p) || !publicinventory.ValidFingerprint(p.Fingerprint) || !bytes.Equal(item.ID, timingRecordID(p.Fingerprint)) || len(p.CertificateID) == 0 || len(p.CertificateID) > 128 || p.PreparedGeneration < 2 || p.PreparedGeneration > item.Generation || p.Failures < 0 || p.Failures > 6 {
		return bad()
	}
	prepared, ok := timingTime(p.PreparedAt)
	started, valid := timingTime(p.StartedAt)
	next, good := timingTime(p.NextCheck)
	if !ok || !valid || !good || started.Before(prepared) || !next.After(started) || next.Sub(started) > providerretry.MaxProviderWait {
		return bad()
	}
	for _, stamp := range []string{p.FallbackAt, p.RenewAt} {
		if _, ok := timingTime(stamp); !ok {
			return bad()
		}
	}
	if p.Pending {
		if p.Outcome != "pending" || p.OutcomeAt != "" || p.Failures < 1 {
			return bad()
		}
	} else {
		out, ok := timingTime(p.OutcomeAt)
		if !ok || out.Before(started) {
			return bad()
		}
		switch p.Outcome {
		case "ari", "unsupported", "error", "interrupted":
		default:
			return bad()
		}
		if p.Outcome == "ari" && (p.ARI == nil || p.Failures != 0 || p.Source != "ari") || p.Outcome == "unsupported" && p.Failures != 0 || (p.Outcome == "error" || p.Outcome == "interrupted") && p.Failures < 1 || p.Outcome != "interrupted" && !next.After(out) {
			return bad()
		}
	}
	if p.Source == "fallback" {
		if p.RenewAt != p.FallbackAt || p.Choice != nil || p.ARI != nil {
			return bad()
		}
	} else if p.Source == "ari" {
		if p.Choice == nil || p.ARI == nil {
			return bad()
		}
		start, ok := timingTime(p.Choice.Start)
		end, valid := timingTime(p.Choice.End)
		computed, good := timingTime(p.Choice.ComputedAt)
		chosen, _ := timingTime(p.RenewAt)
		floor := started
		if !p.Pending {
			floor, _ = timingTime(p.OutcomeAt)
		}
		if !ok || !valid || !good || !end.After(start) || computed.Before(prepared) || computed.After(floor) || chosen.Before(computed) || chosen.Before(start) || !chosen.Before(end) && !chosen.Equal(computed) {
			return bad()
		}
	} else {
		return bad()
	}
	if p.ARI != nil {
		a, ok := timingTime(p.ARI.Start)
		b, valid := timingTime(p.ARI.End)
		checked, good := timingTime(p.ARI.CheckedAt)
		after, ready := timingTime(p.ARI.CheckAfter)
		floor := started
		if !p.Pending {
			floor, _ = timingTime(p.OutcomeAt)
		}
		if !ok || !valid || !good || !ready || !b.After(a) || checked.Before(prepared) || checked.After(floor) || after.Sub(checked) < time.Minute || after.Sub(checked) > 24*time.Hour {
			return bad()
		}
	}
	return p, nil
}

func timingSource(records []publicinventory.Record, fp string) (publicinventory.Record, renewalpolicy.Window, error) {
	for _, r := range records {
		if r.Fingerprint == fp {
			if r.StagingOrigin == nil || !r.StagingOrigin.TestOnly || r.StagingOrigin.Provider != "letsencrypt-staging" || !r.HasPrivateKey || r.KeyStatus != "matched" {
				break
			}
			from, e1 := time.Parse(time.RFC3339, r.NotBefore)
			to, e2 := time.Parse(time.RFC3339, r.NotAfter)
			life := renewalpolicy.Window{Start: from, End: to}
			if e1 != nil || e2 != nil {
				return publicinventory.Record{}, renewalpolicy.Window{}, ErrInvalid
			}
			if _, err := renewalpolicy.FallbackWindow(life); err != nil {
				return publicinventory.Record{}, renewalpolicy.Window{}, ErrInvalid
			}
			return r, life, nil
		}
	}
	return publicinventory.Record{}, renewalpolicy.Window{}, ErrInvalid
}

func authenticateTimingPlans(key, id []byte, m manifest, records []publicinventory.Record) error {
	if len(m.RenewalTimings) > maxRecords {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, item := range m.RenewalTimings {
		p, err := openTimingPayload(key, id, m, item)
		if err != nil || seen[p.Fingerprint] {
			return ErrInvalid
		}
		seen[p.Fingerprint] = true
		r, life, err := timingSource(records, p.Fingerprint)
		if err != nil || r.ImportGeneration > p.PreparedGeneration {
			return ErrInvalid
		}
		certID, err := renewalpolicy.CertificateID(r.DER)
		if err != nil || certID != p.CertificateID {
			return ErrInvalid
		}
		prepared, _ := timingTime(p.PreparedAt)
		verified, err := time.Parse(time.RFC3339, r.StagingOrigin.VerifiedAt)
		fallback, _ := timingTime(p.FallbackAt)
		chosen, _ := timingTime(p.RenewAt)
		if err != nil || prepared.Before(verified) || fallback.Before(life.Start) || !fallback.Before(life.End) || chosen.Before(life.Start) || !chosen.Before(life.End) {
			return ErrInvalid
		}
		window, err := renewalpolicy.FallbackWindow(life)
		if err != nil || fallback.Before(window.Start) || !fallback.Before(window.End) && !fallback.Equal(prepared) {
			return ErrInvalid
		}
		if p.ARI != nil {
			end, _ := timingTime(p.ARI.End)
			if end.After(life.End) {
				return ErrInvalid
			}
		}
		if p.Choice != nil {
			end, _ := timingTime(p.Choice.End)
			computed, _ := timingTime(p.Choice.ComputedAt)
			if end.After(life.End) || !computed.Before(life.End) {
				return ErrInvalid
			}
		}
	}
	return nil
}

func timingReserve(key, id []byte, m manifest) (int, error) {
	if len(m.RenewalTimings) > maxRecords {
		return 0, ErrInvalid
	}
	count := 0
	for _, item := range m.RenewalTimings {
		p, err := openTimingPayload(key, id, m, item)
		if err != nil {
			return 0, err
		}
		if p.Pending {
			count++
		}
	}
	return count, nil
}
func deleteTimingPlan(m *manifest, fp string) {
	id := timingRecordID(fp)
	m.RenewalTimings = slices.DeleteFunc(slices.Clone(m.RenewalTimings), func(item sealedRecord) bool { return bytes.Equal(item.ID, id) })
}

func timingClock(key, id []byte, m manifest, at time.Time, p *timingPayload) bool {
	if _, ok := timingTime(timingStamp(at)); !ok {
		return false
	}
	events, err := openHistory(key, id, m)
	if err != nil {
		return false
	}
	for _, event := range events {
		stamp, err := time.Parse(time.RFC3339, event.At)
		if err != nil || at.Before(stamp) {
			return false
		}
	}
	if p != nil {
		for _, stamp := range []string{p.PreparedAt, p.StartedAt, p.OutcomeAt} {
			if stamp != "" {
				t, ok := timingTime(stamp)
				if !ok || at.Before(t) {
					return false
				}
			}
		}
	}
	wait, err := openStagingWait(key, id, m)
	if err != nil {
		return false
	}
	if wait.ObservedAt != "" {
		seen, _ := timingTime(wait.ObservedAt)
		if at.Before(seen) {
			return false
		}
	}
	return true
}

func readTimingStatusAt(key, id, image []byte, expected uint64, fp string, at time.Time) (RenewalTimingStatus, uint64, error) {
	bad := func(err error) (RenewalTimingStatus, uint64, error) { return RenewalTimingStatus{}, 0, err }
	m, records, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	if expected == 0 || expected != m.Generation {
		return bad(ErrStaleGeneration)
	}
	source, life, err := timingSource(records, fp)
	if err != nil {
		return bad(err)
	}
	verified, timeErr := time.Parse(time.RFC3339, source.StagingOrigin.VerifiedAt)
	if timeErr != nil || at.Before(verified) {
		return bad(ErrInvalid)
	}
	superseded, err := completedRenewalSources(key, id, m)
	if err != nil {
		return bad(err)
	}
	s := RenewalTimingStatus{Fingerprint: fp, State: "not-prepared", Expired: !at.Before(life.End), Superseded: superseded[fp]}
	wait, err := openStagingWait(key, id, m)
	if err != nil {
		return bad(err)
	}
	s.ProviderNotBefore, s.Blocked = wait.NotBefore, wait.Blocked
	var p *timingPayload
	for _, item := range m.RenewalTimings {
		v, err := openTimingPayload(key, id, m, item)
		if err != nil {
			return bad(err)
		}
		if v.Fingerprint == fp {
			p = &v
			break
		}
	}
	if !timingClock(key, id, m, at, p) || at.Before(life.Start) {
		return bad(ErrInvalid)
	}
	if p == nil {
		s.CanRead = !s.Expired && !s.Superseded && stagingWaitReady(wait, at)
		return s, m.Generation, nil
	}
	s.Prepared, s.State, s.Pending, s.CanInterrupt = true, p.Outcome, p.Pending, p.Pending
	s.StartedAt, s.ObservedAt = p.StartedAt, p.OutcomeAt
	s.Source, s.RenewAt, s.FallbackAt, s.NextCheck = p.Source, p.RenewAt, p.FallbackAt, p.NextCheck
	s.Failures = p.Failures
	effective, _ := timingTime(p.RenewAt)
	fresh := false
	if p.ARI != nil {
		s.WindowStart, s.WindowEnd, s.CheckedAt = p.ARI.Start, p.ARI.End, p.ARI.CheckedAt
		after, _ := timingTime(p.ARI.CheckAfter)
		fresh = p.Outcome == "ari" && !p.Pending && !wait.Blocked && at.Before(after)
	}
	if !fresh {
		fallback, _ := timingTime(p.FallbackAt)
		if fallback.Before(effective) {
			effective = fallback
			s.Source = "fallback"
		}
	}
	if wait.NotBefore != "" {
		notBefore, _ := timingTime(wait.NotBefore)
		if effective.Before(notBefore) {
			effective = notBefore
		}
	}
	s.EffectiveAt = timingStamp(effective)
	next, _ := timingTime(p.NextCheck)
	s.CanRead = !p.Pending && !s.Expired && !s.Superseded && stagingWaitReady(wait, at) && !at.Before(next)
	return s, m.Generation, nil
}

func ReadStagingRenewalTiming(key, id, image []byte, expected uint64, fp string) (RenewalTimingStatus, uint64, error) {
	return readTimingStatusAt(key, id, image, expected, fp, time.Now().UTC())
}

func sealTimingPlan(key, id []byte, m manifest, p timingPayload, action string, hint providerretry.Hint, at time.Time) ([]byte, uint64, error) {
	bad := func(err error) ([]byte, uint64, error) {
		return nil, 0, err
	}
	if m.Generation >= maxGeneration {
		return bad(ErrLimit)
	}
	m.Generation++
	plain, err := json.Marshal(p)
	defer clear(plain)
	if err != nil || len(plain) > timingPlainLimit {
		return bad(ErrLimit)
	}
	k, err := timingKey(key, id)
	if err != nil {
		return bad(err)
	}
	defer clear(k)
	item := sealedRecord{ID: timingRecordID(p.Fingerprint), Generation: m.Generation}
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
	if err != nil {
		return bad(err)
	}
	m.RenewalTimings = slices.Clone(m.RenewalTimings)
	found := false
	for i, old := range m.RenewalTimings {
		if bytes.Equal(old.ID, item.ID) {
			m.RenewalTimings[i] = item
			found = true
			break
		}
	}
	if !found {
		m.RenewalTimings = append(m.RenewalTimings, item)
	}
	if err := constrainStagingWait(key, id, &m, hint, at); err != nil {
		return bad(err)
	}
	if err := addEvent(key, &m, action, []string{p.Fingerprint}); err != nil {
		return bad(err)
	}
	image, err := encode(key, m)
	if err != nil {
		return bad(err)
	}
	if _, _, err := decode(key, id, image); err != nil {
		return bad(err)
	}
	return image, m.Generation, nil
}
