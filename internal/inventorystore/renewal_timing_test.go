package inventorystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/providerretry"
	"github.com/denyfirst/rootwell/internal/renewalpolicy"
	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

func timingFixture(t *testing.T) (key, id, image []byte, fp string, at time.Time) {
	t.Helper()
	key, id, _, image, _, fp, at = syntheticCompletion(t)
	at = at.Add(3 * time.Second)
	return
}

func TestRenewalTimingPublicWrappersAndPendingRequireExplicitRetirement(t *testing.T) {
	key, id, _, image, _, fp, _ := syntheticCompletionLifetime(t, 12*time.Hour)
	defer clear(key)
	pending, attempt, s, gen, err := BeginStagingRenewalTiming(key, id, image, 13, fp)
	if err != nil || !s.Pending || gen != 14 {
		t.Fatal("public intent refused", err)
	}
	at, _ := timingTime(s.StartedAt)
	if out, a, _, err := beginTimingAt(key, id, pending, gen, fp, at.Add(7*time.Hour)); err == nil || out != nil || a != nil {
		t.Fatal("unretired intent regained read authority")
	}
	result, status, g, err := ExecuteStagingRenewalTiming(key, id, pending, attempt, func() bool { return true }, func(permit func() bool, der []byte) (renewalrecord.Observation, error) {
		cid, err := renewalpolicy.CertificateID(der)
		if err != nil || !permit() {
			t.Fatal("public receipt source", err)
		}
		return renewalrecord.Observation{CertificateID: cid}, nil
	})
	if err != nil || g != 15 || status.State != "unsupported" || status.Source != "fallback" || status.CanRead {
		t.Fatal("public unsupported result refused", err)
	}
	reread, _, err := ReadStagingRenewalTiming(key, id, result, g, fp)
	if err != nil || reread.RenewAt != status.RenewAt {
		t.Fatal("public read changed choice", err)
	}
	retired, interrupted, ig, err := InterruptStagingRenewalTiming(key, id, pending, 14, fp)
	if err != nil || ig != 15 || interrupted.Pending || interrupted.NextCheck != s.NextCheck || retired == nil {
		t.Fatal("public retirement reset intent", err)
	}
}

func TestRenewalTimingChangedWindowCannotPostponeAndStaleFallsBack(t *testing.T) {
	key, id, image, fp, at := timingFixture(t)
	defer clear(key)
	image, first, gen := timingRunAt(t, key, id, image, fp, at, timingObservation(t, at.Add(time.Second), 45*time.Minute))
	check, _ := timingTime(first.NextCheck)
	stale, _, err := readTimingStatusAt(key, id, image, gen, fp, check)
	if err != nil || stale.Source != "fallback" || stale.EffectiveAt != first.FallbackAt {
		t.Fatal("stale ARI hid local backstop", err)
	}
	image, later, gen := timingRunAt(t, key, id, image, fp, check, timingObservation(t, check.Add(time.Second), 50*time.Minute))
	if gen != 17 || later.RenewAt != first.RenewAt {
		t.Fatal("changed later window postponed saved choice")
	}
	check, _ = timingTime(later.NextCheck)
	image, early, gen := timingRunAt(t, key, id, image, fp, check, timingObservation(t, check.Add(time.Second), time.Minute))
	old, _ := timingTime(later.RenewAt)
	chosen, _ := timingTime(early.RenewAt)
	if !chosen.Before(old) || early.FallbackAt != first.FallbackAt {
		t.Fatal("urgent window failed to advance choice")
	}
	if status, _, err := readTimingStatusAt(key, id, image, gen, fp, at.Add(2*time.Hour)); err != nil || !status.Expired || status.CanRead {
		t.Fatal("expired source gained authority", err)
	}
}

func TestRenewalTimingUntrustedStoredSemanticsNoPartialProjection(t *testing.T) {
	key, id, image, fp, at := timingFixture(t)
	defer clear(key)
	image, _, _ = timingRunAt(t, key, id, image, fp, at, timingObservation(t, at.Add(time.Second), 10*time.Minute))
	for name, mutate := range map[string]func(*timingPayload){
		"identity":         func(p *timingPayload) { p.CertificateID = "other" },
		"generation":       func(p *timingPayload) { p.PreparedGeneration = 1 },
		"timestamp":        func(p *timingPayload) { p.StartedAt = "2026-02-30T00:00:00Z" },
		"future":           func(p *timingPayload) { p.ARI.CheckedAt = timingStamp(at.Add(time.Hour)) },
		"long-check":       func(p *timingPayload) { p.ARI.CheckAfter = timingStamp(at.Add(25 * time.Hour)) },
		"outside-lifetime": func(p *timingPayload) { p.ARI.End = timingStamp(at.Add(2 * time.Hour)) },
		"wrong-choice":     func(p *timingPayload) { p.RenewAt = timingStamp(at.Add(50 * time.Minute)) },
		"wrong-fallback":   func(p *timingPayload) { p.FallbackAt = timingStamp(at) },
		"partial-intent":   func(p *timingPayload) { p.Pending = true },
		"bad-state":        func(p *timingPayload) { p.Outcome = "success" },
		"bad-count":        func(p *timingPayload) { p.Failures = 7 },
	} {
		t.Run(name, func(t *testing.T) {
			m, _, err := decode(key, id, image)
			if err != nil {
				t.Fatal(err)
			}
			p, _, err := lookupTiming(key, id, m, fp)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&p)
			plain, _ := json.Marshal(p)
			k, err := timingKey(key, id)
			if err != nil {
				t.Fatal(err)
			}
			m.RenewalTimings[0].Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, m.RenewalTimings[0]), plain)
			clear(k)
			clear(plain)
			if err != nil {
				t.Fatal(err)
			}
			bad, err := encode(key, m)
			if err != nil {
				return
			} // an earlier authenticated bound may refuse
			if s, g, err := ReadStagingRenewalTiming(key, id, bad, m.Generation, fp); err == nil || s.Prepared || g != 0 {
				t.Fatal("malformed sealed timing exposed output")
			}
		})
	}
	for _, mutate := range []func(*manifest){
		func(m *manifest) { m.RenewalTimings = append(m.RenewalTimings, m.RenewalTimings[0]) },
		func(m *manifest) { m.RenewalTimings[0].ID[0] ^= 1 },
		func(m *manifest) { m.RenewalTimings[0].Generation++ },
		func(m *manifest) { m.RenewalTimings[0].Ciphertext[30] ^= 1 },
		func(m *manifest) { m.Materials = nil },
	} {
		m, _, err := decode(key, id, image)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&m)
		bad, err := encode(key, m)
		if err != nil {
			continue
		}
		if records, g, err := Open(key, id, bad); err == nil || records != nil || g != 0 {
			t.Fatal("whole image skipped timing authentication")
		}
	}
}

func TestRenewalTimingReservationsProviderBoundsAndPrivacy(t *testing.T) {
	key, id, image, fp, at := timingFixture(t)
	defer clear(key)
	pending, _, _, err := beginTimingAt(key, id, image, 13, fp, at)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := decode(key, id, pending)
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := dnsTotalReserve(key, id, m, dnsPlanPayload{})
	if err != nil || reserve != 1 || reservedImageBytes(key, id, m) != timingOutcomeBytes {
		t.Fatal("outcome capacity not reserved", err)
	}
	status, err := ReadAutomationStatus(key, id, pending, at.Add(time.Second))
	if err != nil || status.Capacity.EventsReserved != 1 {
		t.Fatal("overview double-counted or lost timing reserve", err)
	}
	// A source may consume the last two generations only as intent + outcome.
	base, _, _ := decode(key, id, image)
	base.History = nil
	base.Generation = maxGeneration - 1
	near, err := encode(key, base)
	if err != nil {
		t.Fatal(err)
	}
	if out, _, _, err := beginTimingAt(key, id, near, base.Generation, fp, at); !errors.Is(err, ErrLimit) || out != nil {
		t.Fatal("intent consumed reserved final generation", err)
	}
	base.Generation--
	near, err = encode(key, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, g := timingRunAt(t, key, id, near, fp, at, timingObservation(t, at.Add(time.Second), 10*time.Minute)); g != maxGeneration {
		t.Fatal("reserved final outcome could not commit")
	}
	for _, hint := range []providerretry.Hint{{Blocked: true}, {NotBefore: at.Add(8 * 24 * time.Hour)}} {
		blocked, s, g := timingRunAt(t, key, id, image, fp, at, func(func() bool, []byte) (renewalrecord.Observation, error) {
			return renewalrecord.Observation{}, &renewalrecord.Failure{Hint: hint}
		})
		if !s.Blocked || s.CanRead {
			t.Fatal("unbounded provider wait permitted read")
		}
		if out, _, _, err := beginTimingAt(key, id, blocked, g, fp, at.Add(time.Minute)); !errors.Is(err, ErrTimingBlocked) || out != nil {
			t.Fatal("blocked policy bypassed", err)
		}
		deleted, _, err := DeleteRecord(key, id, blocked, fp, g)
		if err != nil {
			t.Fatal(err)
		}
		global, _, err := readStagingWaitAt(key, id, deleted, at.Add(2*time.Minute))
		if err != nil || !global.Blocked || global.Ready {
			t.Fatal("deletion reset permanent barrier", err)
		}
	}
}
func timingObservation(t *testing.T, at time.Time, offset time.Duration) RenewalTimingOperation {
	t.Helper()
	return func(permit func() bool, der []byte) (renewalrecord.Observation, error) {
		if !permit() {
			t.Fatal("legitimate permit refused")
		}
		id, err := renewalpolicy.CertificateID(der)
		if err != nil {
			t.Fatal(err)
		}
		return renewalrecord.Observation{CertificateID: id, Available: true, Information: renewalpolicy.Information{Window: renewalpolicy.Window{Start: at.Add(offset), End: at.Add(offset + 5*time.Minute)}, CheckedAt: at, CheckAfter: at.Add(time.Minute)}}, nil
	}
}
func timingRunAt(t *testing.T, key, id, image []byte, fp string, at time.Time, use RenewalTimingOperation) ([]byte, RenewalTimingStatus, uint64) {
	t.Helper()
	_, gen, err := Open(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	next, a, g, err := beginTimingAt(key, id, image, gen, fp, at)
	if err != nil || g != gen+1 {
		t.Fatal("legitimate timing intent refused", err)
	}
	next, g, err = executeTimingAt(key, id, next, a, func() bool { return true }, use, func() time.Time { return at.Add(time.Second) })
	if err != nil {
		t.Fatal("legitimate timing outcome refused", err)
	}
	s, sg, err := readTimingStatusAt(key, id, next, g, fp, at.Add(2*time.Second))
	if err != nil || g != sg {
		t.Fatal("legitimate timing status refused", err)
	}
	return next, s, g
}

func TestRenewalTimingDurableExactSourceSingleChoiceAndNoSecretBorrow(t *testing.T) {
	key, id, image, fp, at := timingFixture(t)
	defer clear(key)
	original := image
	before := bytes.Clone(image)
	initial, gen, err := readTimingStatusAt(key, id, image, 13, fp, at)
	if err != nil || !initial.CanRead || initial.Prepared || gen != 13 || !bytes.Equal(image, before) {
		t.Fatal("legitimate initial timing refused", err)
	}
	completed, s, g := timingRunAt(t, key, id, image, fp, at, timingObservation(t, at.Add(time.Second), 10*time.Minute))
	if g != 15 || !s.Prepared || s.Pending || s.Source != "ari" || s.State != "ari" || s.CanRead || s.Failures != 0 || s.RenewAt == "" || s.FallbackAt == "" || s.EffectiveAt != s.RenewAt {
		t.Fatal("timing observation not saved", s)
	}
	renew, fallback := s.RenewAt, s.FallbackAt
	windowAt := at.Add(time.Second)
	for n := 0; n < 3; n++ {
		next, _ := timingTime(s.NextCheck)
		image, s, g = timingRunAt(t, key, id, completed, fp, next, func(permit func() bool, der []byte) (renewalrecord.Observation, error) {
			result, _ := timingObservation(t, windowAt, 10*time.Minute)(permit, der)
			result.Information.CheckedAt = next.Add(time.Second)
			result.Information.CheckAfter = next.Add(2 * time.Minute)
			return result, nil
		})
		if s.RenewAt != renew || s.FallbackAt != fallback {
			t.Fatal("same-window refresh rerolled saved time")
		}
		completed = image
	}
	public, _ := json.Marshal(s)
	m, _, err := decode(key, id, completed)
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := lookupTiming(key, id, m, fp)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PRIVATE KEY", p.CertificateID, "private_key", "acme/order"} {
		if bytes.Contains(public, []byte(secret)) || bytes.Contains(completed, []byte(secret)) {
			t.Fatal("timing exposed secret/internal material")
		}
	}
	if !bytes.Equal(original, before) {
		t.Fatal("source image mutated")
	}
	// Untrusted bytes, stale source and invalid identity never release partial
	// metadata or a lease (the complete image authenticates before projection).
	for _, tc := range []struct {
		key, id, image []byte
		gen            uint64
		fp             string
		at             time.Time
	}{
		{key, id, completed, g - 1, fp, at.Add(10 * time.Minute)},
		{make([]byte, 32), id, completed, g, fp, at.Add(10 * time.Minute)},
		{key, make([]byte, 16), completed, g, fp, at.Add(10 * time.Minute)},
		{key, id, append(bytes.Clone(completed), '\n'), g, fp, at.Add(10 * time.Minute)},
		{key, id, completed, g, strings.Repeat("A", 64), at.Add(10 * time.Minute)},
		{key, id, completed, g, fp, at.Add(-time.Hour)},
	} {
		out, a, gen, err := beginTimingAt(tc.key, tc.id, tc.image, tc.gen, tc.fp, tc.at)
		if err == nil || out != nil || a != nil || gen != 0 {
			t.Fatal("bad source released timing intent")
		}
	}
}

func TestRenewalTimingWaitInterruptedReadAndProviderBarrierSurviveDeletion(t *testing.T) {
	key, id, image, fp, at := timingFixture(t)
	defer clear(key)
	pending, a, g, err := beginTimingAt(key, id, image, 13, fp, at)
	if err != nil {
		t.Fatal(err)
	}
	s, _, err := readTimingStatusAt(key, id, pending, g, fp, at.Add(time.Second))
	if err != nil || !s.Pending || !s.CanInterrupt || s.CanRead || s.Failures != 1 {
		t.Fatal("pending intent lost", err, s)
	}
	if out, _, _, err := beginTimingAt(key, id, pending, g, fp, at.Add(time.Second)); !errors.Is(err, ErrTimingWait) || out != nil {
		t.Fatal("pending wait bypassed")
	}
	interrupted, ig, err := interruptTimingAt(key, id, pending, g, fp, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	i, _, err := readTimingStatusAt(key, id, interrupted, ig, fp, at.Add(2*time.Second))
	if err != nil || i.Pending || i.State != "interrupted" || i.NextCheck != s.NextCheck || i.FallbackAt != s.FallbackAt || i.Failures != 1 {
		t.Fatal("interrupt reset wait/choice", err, i)
	}
	called := false
	if out, _, err := executeTimingAt(key, id, interrupted, a, func() bool { return true }, func(func() bool, []byte) (renewalrecord.Observation, error) {
		called = true
		return renewalrecord.Observation{}, nil
	}, func() time.Time { return at.Add(2 * time.Second) }); err == nil || out != nil || called {
		t.Fatal("interrupted lease regained read authority")
	}
	// Use an independent fresh fixture: a CA wait must survive deleting the
	// source, rather than allowing selection/deletion to erase provider policy.
	key2, id2, image2, fp2, now := timingFixture(t)
	defer clear(key2)
	waitUntil := now.Add(3 * time.Hour)
	limited, s, g := timingRunAt(t, key2, id2, image2, fp2, now, func(func() bool, []byte) (renewalrecord.Observation, error) {
		return renewalrecord.Observation{}, &renewalrecord.Failure{Temporary: true, Hint: providerretry.Hint{NotBefore: waitUntil}}
	})
	if s.State != "error" || s.Failures != 1 || s.ProviderNotBefore != timingStamp(waitUntil) || s.CanRead {
		t.Fatal("provider wait lost", s)
	}
	deleted, dg, err := DeleteRecord(key2, id2, limited, fp2, g)
	if err != nil {
		t.Fatal(err)
	}
	policy, pg, err := readStagingWaitAt(key2, id2, deleted, now.Add(3*time.Second))
	if err != nil || pg != dg || policy.Ready || policy.NotBefore != s.ProviderNotBefore {
		t.Fatal("deletion reset provider wait", err, policy)
	}
	m, records, err := decode(key2, id2, deleted)
	if err != nil || len(records) != 0 || len(m.RenewalTimings) != 0 || len(m.StagingProviderWait) != 1 {
		t.Fatal("deletion lost global policy or retained source metadata", err)
	}
	policy, _, err = readStagingWaitAt(key2, id2, deleted, waitUntil)
	if err != nil || !policy.Ready {
		t.Fatal("elapsed provider wait stayed locked", err)
	}
}

func TestRenewalTimingLeaseNoReplayRevocationAndMalformedReceipt(t *testing.T) {
	key, id, image, fp, at := timingFixture(t)
	defer clear(key)
	for _, mode := range []string{"wrong-id", "partial-error", "revoked", "late", "wrong-image"} {
		t.Run(mode, func(t *testing.T) {
			pending, a, _, err := beginTimingAt(key, id, image, 13, fp, at)
			if err != nil {
				t.Fatal(err)
			}
			permit := true
			clock := at.Add(time.Second)
			calls := 0
			use := func(allowed func() bool, der []byte) (renewalrecord.Observation, error) {
				calls++
				result, _ := timingObservation(t, at.Add(time.Second), 10*time.Minute)(allowed, der)
				switch mode {
				case "wrong-id":
					result.CertificateID = "wrong"
				case "partial-error":
					return result, errors.New("private-error-sentinel")
				case "revoked":
					permit = false
				case "late":
					clock = at.Add(time.Minute)
				}
				return result, nil
			}
			if mode == "wrong-image" {
				pending = append(bytes.Clone(pending), '\n')
			}
			out, g, err := executeTimingAt(key, id, pending, a, func() bool { return permit }, use, func() time.Time { return clock })
			if err == nil || out != nil || g != 0 || strings.Contains(err.Error(), "sentinel") || mode == "wrong-image" && calls != 0 {
				t.Fatal("bad receipt released partial result")
			}
			copied := *a
			if out, _, err := executeTimingAt(key, id, pending, &copied, func() bool { return true }, use, func() time.Time { return at.Add(time.Second) }); err == nil || out != nil {
				t.Fatal("consumed copied lease replayed")
			}
		})
	}
	if s, g, err := readTimingStatusAt(key, id, []byte("bad"), 13, fp, at); err == nil || g != 0 || !reflect.DeepEqual(s, RenewalTimingStatus{}) {
		t.Fatal("bad image exposed status")
	}
}

func TestRenewalTimingConcurrentLeaseAndImportedSourceRefusal(t *testing.T) {
	key, id, image, fp, at := timingFixture(t)
	defer clear(key)
	pending, a, _, err := beginTimingAt(key, id, image, 13, fp, at)
	if err != nil {
		t.Fatal(err)
	}
	var calls, successes atomic.Int32
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			copy := *a
			next, _, err := executeTimingAt(key, id, pending, &copy, func() bool { return true }, func(func() bool, []byte) (renewalrecord.Observation, error) {
				calls.Add(1)
				return renewalrecord.Observation{}, errors.New("not-reflected-sentinel")
			}, func() time.Time { return at.Add(time.Second) })
			if err == nil && next != nil {
				successes.Add(1)
			}
		})
	}
	workers.Wait()
	if calls.Load() != 1 || successes.Load() != 1 {
		t.Fatal("copied concurrent lease gained duplicate authority")
	}
	records, _, err := Open(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Create(key, id)
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err = Append(key, id, plain, records[0].DER, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if out, a, _, err := beginTimingAt(key, id, plain, 2, fp, at); err == nil || out != nil || a != nil {
		t.Fatal("ordinary import manufactured staging authority")
	}
}

func TestRenewalTimingProviderWaitBoundariesAndAuthenticatedTamper(t *testing.T) {
	key, id, image, fp, at := timingFixture(t)
	defer clear(key)
	at = at.Add(123456789 * time.Nanosecond)
	until := at.Add(time.Second + 7*24*time.Hour)
	image, s, _ := timingRunAt(t, key, id, image, fp, at, func(func() bool, []byte) (renewalrecord.Observation, error) {
		return renewalrecord.Observation{}, &renewalrecord.Failure{Hint: providerretry.Hint{NotBefore: until}}
	})
	if s.Blocked || s.ProviderNotBefore != timingStamp(until) {
		t.Fatal("legitimate fractional maximum wait blocked")
	}
	for _, mode := range []string{"account", "future-generation", "timestamp", "duplicate", "context", "ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			m, _, err := decode(key, id, image)
			if err != nil {
				t.Fatal(err)
			}
			p, err := openStagingWait(key, id, m)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "account", "timestamp":
				if mode == "account" {
					p.Account = strings.Repeat("AA:", 31) + "AA"
				} else {
					p.ObservedAt = "2020-01-01T00:00:00Z"
					p.NotBefore = "2020-01-02T00:00:00Z"
				}
				plain, _ := json.Marshal(p)
				k, err := stagingWaitKey(key, id)
				if err != nil {
					t.Fatal(err)
				}
				m.StagingProviderWait[0].Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, m.StagingProviderWait[0]), plain)
				clear(k)
				clear(plain)
				if err != nil {
					t.Fatal(err)
				}
			case "future-generation":
				m.StagingProviderWait[0].Generation++
			case "duplicate":
				m.StagingProviderWait = append(m.StagingProviderWait, m.StagingProviderWait[0])
			case "context":
				m.StagingProviderWait[0].ID[0] ^= 1
			case "ciphertext":
				m.StagingProviderWait[0].Ciphertext[30] ^= 1
			}
			bad, err := encode(key, m)
			if err != nil {
				t.Fatal(err)
			}
			if records, g, err := Open(key, id, bad); err == nil || records != nil || g != 0 {
				t.Fatal("authenticated bad global wait opened")
			}
		})
	}
}

func FuzzRenewalTimingPayload(f *testing.F) {
	key, id := bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 16)
	fp := strings.Repeat("AA:", 31) + "AA"
	m := manifest{Generation: 2}
	seed, _ := json.Marshal(timingPayload{Fingerprint: fp, CertificateID: "AQID.AIA", PreparedAt: "2026-10-26T00:00:00Z", PreparedGeneration: 2, FallbackAt: "2026-10-26T12:00:00Z", Source: "fallback", RenewAt: "2026-10-26T12:00:00Z", Pending: true, StartedAt: "2026-10-26T00:00:00Z", Outcome: "pending", Failures: 1, NextCheck: "2026-10-26T06:00:00Z"})
	f.Add(seed)
	f.Add([]byte(`{"pending":true,"pending":false}`))
	f.Add([]byte("bad"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > timingPlainLimit+1 {
			t.Skip()
		}
		k, err := timingKey(key, id)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(k)
		item := sealedRecord{ID: timingRecordID(fp), Generation: 2}
		item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), data)
		if len(data) == 0 {
			if !errors.Is(err, inventoryseal.ErrSize) || item.Ciphertext != nil {
				t.Fatal("empty payload was not refused before encryption")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		p, err := openTimingPayload(key, id, m, item)
		if err != nil && !reflect.DeepEqual(p, timingPayload{}) {
			t.Fatal("malformed payload exposed partial output")
		}
		if err == nil && (p.Fingerprint != fp || p.Failures < 0 || p.Failures > 6) {
			t.Fatal("payload escaped identity or retry bounds")
		}
	})
}

func TestRenewalTimingAddsToDNSIssuanceReserveAndRetiresSupersededSource(t *testing.T) {
	key, id, _, image, fp := renewalFixture(t)
	defer clear(key)
	at := time.Now().UTC()
	image, _, gen, err := beginTimingAt(key, id, image, 15, fp, at)
	if err != nil {
		t.Fatal(err)
	}
	info := orderInstructionsFixture()
	info.URL = acmeorder.Origin + "/acme/order/1234/9999"
	image, _, gen, err = UpdateStagingOrder(key, id, image, gen, info.URL, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = UpdateStagingOrder(key, id, image, gen, "", &info, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = ChangeCloudflareConfig(key, id, image, gen, configZoneID, "example.com", []byte(configToken), false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = PrepareStagingDNSPlan(key, id, image, gen)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, gen, err = BeginStagingDNSAttempt(key, id, image, gen, 0)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = UpdateStagingOrder(key, id, image, gen, "", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = BeginStagingValidation(key, id, image, gen, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = FinishStagingValidation(key, id, image, gen, acmeorder.Validation{URL: info.URL, Expires: info.Expires, OrderStatus: "ready", Statuses: []string{"valid", "valid"}})
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = PrepareStagingCertificateRequest(key, id, image, gen)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, gen, err = BeginStagingIssuance(key, id, image, gen, false)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := openDNSPlan(key, id, m)
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := dnsTotalReserve(key, id, m, dns)
	if err != nil || reserve != dnsPlanReserve(dns)+2 || reservedImageBytes(key, id, m) != dnsReservedBytes(key, id, m)+issuanceByteReserve+timingOutcomeBytes {
		t.Fatal("timing stole DNS or issuance reserve", err)
	}
	image, _, gen = completeRenewalFixture(t, key, id, image, gen)
	s, _, err := readTimingStatusAt(key, id, image, gen, fp, time.Now().UTC().Add(time.Second))
	if err != nil || !s.Superseded || !s.Pending || s.CanRead || !s.CanInterrupt {
		t.Fatal("retained original regained read authority or lost retirement", err)
	}
	image, gen, err = interruptTimingAt(key, id, image, gen, fp, time.Now().UTC().Add(2*time.Second))
	if err != nil {
		t.Fatal("superseded intent could not retire", err)
	}
	s, _, err = readTimingStatusAt(key, id, image, gen, fp, time.Now().UTC().Add(3*time.Second))
	if err != nil || s.Pending || !s.Superseded || s.CanRead {
		t.Fatal("retirement revived superseded source", err)
	}
}
