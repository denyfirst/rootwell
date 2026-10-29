package inventorystore

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func cycleFixture() (RenewalCycle, time.Time) {
	at := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	fp := strings.Repeat("AB:", 31) + "AB"
	s := RenewalCycle{Generation: 14, Fingerprint: fp, Domains: []string{"example.com"}, AccountReady: true, ConfigGeneration: 3, Zone: "example.com",
		OrderState: "not-started", Issuance: IssuanceStatus{State: "not-started"}, EventsLeft: 1024, GenerationsLeft: 999986, BytesLeft: 96 << 20, RecordsLeft: 10, ClosuresLeft: 30,
		Timing: RenewalTimingStatus{Fingerprint: fp, Prepared: true, State: "unsupported", EffectiveAt: timingStamp(at.Add(-time.Minute))}}
	return s, at
}

func cycleNext(t *testing.T, s RenewalCycle, at time.Time, action string) CycleDecision {
	t.Helper()
	d := DecideRenewalCycle(s, RenewalCycleEvents, RenewalCycleBytes, at)
	if d.Action != action {
		t.Fatalf("wanted %s, got %+v", action, d)
	}
	return d
}

func TestRenewalCycleSequenceOneOrderNewKeyAndOwnedCleanup(t *testing.T) {
	s, at := cycleFixture()
	cycleNext(t, s, at, "order")
	s.OrderState, s.OrderSource = "request-pending", s.Fingerprint
	cycleNext(t, s, at, "pause") // no new order for a lost Location
	s.OrderState = "order-known"
	cycleNext(t, s, at, "order-read")
	s.OrderState, s.RequiredDNS = "dns-ready", true
	cycleNext(t, s, at, "dns-plan")
	s.DNS = DNSPlanStatus{Prepared: true, Records: []DNSPlanRecordStatus{{State: "new"}, {State: "borrowed"}}}
	if d := cycleNext(t, s, at, "dns-add"); d.Index != 0 {
		t.Fatal("wrong required row")
	}
	s.DNS.Records[0].State, s.DNS.Records[0].Attempts = "creating", 1
	cycleNext(t, s, at, "dns-check") // scoped read, never POST again
	s.DNS.Records[0].State = "created"
	cycleNext(t, s, at, "ack")
	s.OrderState = "dns-acknowledged"
	cycleNext(t, s, at, "validate")
	s.OrderState = "validation-pending"
	cycleNext(t, s, at, "validation-read")
	s.OrderState = "validation-waiting"
	cycleNext(t, s, at, "validation-read")
	s.OrderState = "domain-verified"
	cycleNext(t, s, at, "key")
	s.KeyPrepared = true
	cycleNext(t, s, at, "certificate")
	s.Issuance.State = "issuance-pending"
	cycleNext(t, s, at, "certificate-read")
	s.Issuance.State = "awaiting-certificate"
	cycleNext(t, s, at, "certificate-read")
	s.Issuance.State, s.SavedFingerprint = "certificate-saved", strings.Repeat("CD:", 31)+"CD"
	s.Timing.Superseded, s.Timing.Expired, s.Timing.Blocked = true, true, true
	s.Timing.ProviderNotBefore = timingStamp(at.Add(7 * 24 * time.Hour))
	cycleNext(t, s, at, "dns-cleanup") // cleanup independent of CA/source expiry
	s.DNS.Records[0].State, s.DNS.Records[0].CleanupAttempts = "deleting", 1
	cycleNext(t, s, at, "dns-check")
	s.DNS.Records[0].State = "deleted"
	cycleNext(t, s, at, "complete")
}

func TestRenewalCycleRefusesAmbiguityExhaustionAndCapacity(t *testing.T) {
	for name, change := range map[string]func(*RenewalCycle){
		"account":          func(s *RenewalCycle) { s.AccountReady = false },
		"other-reserved":   func(s *RenewalCycle) { s.OtherPending = true },
		"config":           func(s *RenewalCycle) { s.ConfigGeneration = 0 },
		"zone":             func(s *RenewalCycle) { s.Zone = "other.example" },
		"source-expired":   func(s *RenewalCycle) { s.Timing.Expired = true },
		"superseded":       func(s *RenewalCycle) { s.Timing.Superseded = true },
		"pending-timing":   func(s *RenewalCycle) { s.Timing.Pending = true },
		"blocked":          func(s *RenewalCycle) { s.Timing.Blocked = true },
		"lost-timing":      func(s *RenewalCycle) { s.Timing.State = "interrupted" },
		"bad-time":         func(s *RenewalCycle) { s.Timing.EffectiveAt = "tomorrow" },
		"active-unrelated": func(s *RenewalCycle) { s.OrderState = "dns-ready" },
		"unclosed-expired": func(s *RenewalCycle) {
			s.OrderState = "dns-ready"
			s.OrderSource = s.Fingerprint
			s.Close.Reason = "expired"
		},
		"closure":          func(s *RenewalCycle) { s.ClosuresLeft = 0 },
		"close-and-future": func(s *RenewalCycle) { s.OrderState = "domain-verified"; s.Close.Available = true; s.ClosuresLeft = 1 },
		"events":           func(s *RenewalCycle) { s.EventsLeft = RenewalCycleEvents - 1 },
		"generation":       func(s *RenewalCycle) { s.GenerationsLeft = RenewalCycleEvents - 1 },
		"bytes":            func(s *RenewalCycle) { s.BytesLeft = RenewalCycleBytes - 1 },
		"records":          func(s *RenewalCycle) { s.RecordsLeft = 0 },
		"invalid-names":    func(s *RenewalCycle) { s.Domains = nil },
	} {
		t.Run(name, func(t *testing.T) { s, at := cycleFixture(); change(&s); cycleNext(t, s, at, "pause") })
	}
	for _, state := range []string{"creating", "deleting"} {
		for _, mode := range []string{"blocked", "limit", "recovery", "maintenance"} {
			t.Run(state+mode, func(t *testing.T) {
				s, at := cycleFixture()
				s.OrderState, s.OrderSource = "dns-ready", s.Fingerprint
				r := DNSPlanRecordStatus{State: state}
				if state == "deleting" {
					s.Issuance.State, s.SavedFingerprint = "certificate-saved", s.Fingerprint
				}
				switch mode {
				case "blocked":
					r.Blocked, r.CleanupBlocked = true, true
				case "limit":
					r.Attempts, r.CleanupAttempts = 6, 6
				case "recovery":
					r.Recovery = &DNSRecoveryStatus{}
				case "maintenance":
					r.Maintenance = &DNSMaintenanceStatus{}
				}
				s.DNS = DNSPlanStatus{Prepared: true, Records: []DNSPlanRecordStatus{r}}
				cycleNext(t, s, at, "pause")
			})
		}
	}
}

func TestRenewalCycleWaitsDoNotReplayAndBudgetFundsItsOwnWrites(t *testing.T) {
	s, at := cycleFixture()
	s.Timing.ProviderNotBefore = timingStamp(at.Add(2 * time.Hour))
	if d := cycleNext(t, s, at, "wait"); d.Next != s.Timing.ProviderNotBefore {
		t.Fatal("CA hold shortened")
	}
	s.Timing.ProviderNotBefore = ""
	s.Timing.EffectiveAt = timingStamp(at.Add(time.Hour))
	s.Timing.NextCheck = timingStamp(at.Add(5 * time.Minute))
	if d := cycleNext(t, s, at, "wait"); d.Next != s.Timing.NextCheck {
		t.Fatal("missed earlier ARI check")
	}
	s.Timing.CanRead = true
	cycleNext(t, s, at, "timing")
	s.Timing.EffectiveAt = timingStamp(at)
	s.OrderState = "domain-verified"
	s.Close.Available = true
	cycleNext(t, s, at, "close")
	s.OrderState = "not-started"
	s.EventsLeft = RenewalCycleEvents - 10
	s.GenerationsLeft = RenewalCycleEvents - 10
	s.BytesLeft = RenewalCycleBytes - 1024
	if d := DecideRenewalCycle(s, RenewalCycleEvents-10, RenewalCycleBytes-1024, at); d.Action != "order" {
		t.Fatal("used budget was required again", d)
	}
	s.OrderSource = s.Fingerprint
	s.OrderState = "dns-ready"
	s.RequiredDNS = true
	s.DNS = DNSPlanStatus{Prepared: true, Records: []DNSPlanRecordStatus{{State: "creating", Attempts: 2, NotBefore: timingStamp(at.Add(30 * time.Minute))}}}
	if d := DecideRenewalCycle(s, RenewalCycleEvents-10, RenewalCycleBytes-1024, at); d.Action != "wait" {
		t.Fatal("unknown create replayed", d)
	}
}

func TestRenewalCycleResumeDoesNotReprovisionAfterCAValidationOrHideExpiry(t *testing.T) {
	s, at := cycleFixture()
	s.OrderSource, s.OrderState, s.RequiredDNS = s.Fingerprint, "domain-verified", true
	cycleNext(t, s, at, "key") // manual DNS was already checked by the CA
	s.OrderState = "validation-pending"
	cycleNext(t, s, at, "validation-read")
	s.DNS = DNSPlanStatus{Prepared: true, Records: []DNSPlanRecordStatus{{State: "new"}}}
	cycleNext(t, s, at, "pause")
	s.DNS.Records[0].State = "creating"
	s.DNS.Records[0].Attempts = 1
	cycleNext(t, s, at, "dns-check")
	s.DNS.Records[0].State = "created"
	s.Close.Reason = "dns-cleanup-needed"
	s.OrderExpires = timingStamp(at)
	if d := cycleNext(t, s, at, "pause"); d.Reason != "request-expired" {
		t.Fatal("DNS cleanup masked expiry", d)
	}
	s.OrderExpires = timingStamp(at.Add(time.Hour))
	s.Issuance.Expires = timingStamp(at)
	cycleNext(t, s, at, "pause")
}

func TestRenewalCycleLongCAWaitCannotHideAnAlreadyUncertainWrite(t *testing.T) {
	for _, state := range []string{"request-pending", "validation-failed", "domain-verified"} {
		s, at := cycleFixture()
		s.OrderSource, s.OrderState = s.Fingerprint, state
		s.Timing.ProviderNotBefore = timingStamp(at.Add(7 * 24 * time.Hour))
		if state == "domain-verified" {
			s.KeyPrepared = true
			s.Issuance.State = "issuance-failed"
		}
		cycleNext(t, s, at, "pause")
	}
	s, at := cycleFixture()
	s.OrderSource, s.OrderState = s.Fingerprint, "order-known"
	s.Timing.ProviderNotBefore = timingStamp(at.Add(time.Hour))
	cycleNext(t, s, at, "wait") // known same-order reads still respect the hold
}

func TestRenewalCycleAuthenticatedMetadataZeroOnFailure(t *testing.T) {
	key, id, image, fp, at := timingFixture(t)
	defer clear(key)
	if live, err := ReadRenewalCycle(key, id, image, 13, fp); err != nil || live.Fingerprint != fp {
		t.Fatal("current-clock public read", err)
	}
	s, err := readRenewalCycleAt(key, id, image, 13, fp, at)
	if err != nil || s.Generation != 13 || s.Fingerprint != fp || s.SavedFingerprint != fp || s.OrderState != "domain-verified" || s.ConfigGeneration != 0 {
		t.Fatal("valid source refused", err, s)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private_key", "csr", "BEGIN", "https://", "token", "provider_id", "value", "note"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("private scope projected", forbidden)
		}
	}
	for name, test := range map[string]struct {
		image []byte
		gen   uint64
		fp    string
		at    time.Time
	}{
		"stale": {image, 12, fp, at}, "identity": {image, 13, strings.Repeat("00:", 31) + "00", at}, "clock": {image, 13, fp, at.Add(-24 * time.Hour)}, "corrupt": {[]byte("{}"), 13, fp, at},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readRenewalCycleAt(key, id, test.image, test.gen, test.fp, test.at)
			if err == nil || !reflect.DeepEqual(got, RenewalCycle{}) {
				t.Fatal("partial metadata on refusal", err)
			}
			if name == "stale" && !errors.Is(err, ErrStaleGeneration) {
				t.Fatal(err)
			}
		})
	}
}
