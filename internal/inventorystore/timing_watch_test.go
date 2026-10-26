package inventorystore

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestTimingWatchReadinessRecoveryIsReadOnlyAndExactSource(t *testing.T) {
	k, id, image, fp, at := timingFixture(t)
	defer clear(k)
	before := bytes.Clone(image)
	p, err := ReadTimingReadiness(k, id, image, 13, fp, at)
	if err != nil || p.Generation != 13 || !p.CanStart || p.Recovery != "none" || p.Timing.Fingerprint != fp || !bytes.Equal(before, image) {
		t.Fatal("valid exact source refused or changed", err, p.Reason)
	}
	for _, bad := range []struct {
		k, id, image []byte
		gen          uint64
		fp           string
	}{{k, id, image, 12, fp}, {k, id, image, 13, "other"}, {bytes.Repeat([]byte{1}, 32), id, image, 13, fp}, {k, bytes.Repeat([]byte{1}, 16), image, 13, fp}, {k, id, []byte("malformed"), 13, fp}} {
		out, err := ReadTimingReadiness(bad.k, bad.id, bad.image, bad.gen, bad.fp, at)
		if err == nil || !reflect.DeepEqual(out, TimingReadiness{}) {
			t.Fatal("unsafe source or partial readiness accepted")
		}
	}
	pending, _, gen, err := beginTimingAt(k, id, image, 13, fp, at)
	if err != nil {
		t.Fatal(err)
	}
	p, err = ReadTimingReadiness(k, id, pending, gen, fp, at)
	if err != nil || p.CanStart || p.Reason != "timing-interrupted" || p.Recovery != "timing" {
		t.Fatal("pending read automatically retried", err)
	}
	retired, gen, err := interruptTimingAt(k, id, pending, gen, fp, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	p, err = ReadTimingReadiness(k, id, retired, gen, fp, at.Add(time.Second))
	if err != nil || !p.CanStart || p.Reason != "provider-wait" || p.NextCheck == "" {
		t.Fatal("retirement erased wait or cannot wait safely", err)
	}
}

func TestTimingWatchRecoveryPolicyNeverResetsOrReplays(t *testing.T) {
	at := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	a := AutomationStatus{Generation: 13, AccountReady: true, DNS: "none", Request: "close-needed", Capacity: AutomationSpace{EventsFree: 10, GenerationsFree: 10, BytesFree: 100000}}
	s := RenewalTimingStatus{Fingerprint: "public-source"}
	for _, tc := range []struct {
		name, reason, recovery string
		edit                   func(*RenewalTimingStatus, *AutomationStatus)
	}{
		{"expired", "source-ended", "certificates", func(s *RenewalTimingStatus, _ *AutomationStatus) { s.Expired = true }},
		{"replaced", "source-ended", "certificates", func(s *RenewalTimingStatus, _ *AutomationStatus) { s.Superseded = true }},
		{"blocked", "provider-maintenance", "maintenance", func(s *RenewalTimingStatus, _ *AutomationStatus) { s.Blocked = true }},
		{"pending", "timing-interrupted", "timing", func(s *RenewalTimingStatus, _ *AutomationStatus) { s.Pending = true }},
		{"account", "account-unavailable", "request", func(_ *RenewalTimingStatus, a *AutomationStatus) { a.AccountReady = false }},
		{"dns-unknown", "dns-unconfirmed", "dns", func(_ *RenewalTimingStatus, a *AutomationStatus) { a.DNS = "unknown" }},
		{"dns-blocked", "dns-maintenance", "maintenance", func(_ *RenewalTimingStatus, a *AutomationStatus) { a.DNS = "maintenance" }},
		{"dns-owned", "dns-cleanup", "dns", func(_ *RenewalTimingStatus, a *AutomationStatus) { a.DNS = "cleanup-needed" }},
		{"unknown-request", "request-unconfirmed", "request", func(_ *RenewalTimingStatus, a *AutomationStatus) { a.Request = "unknown" }},
		{"active-request", "request-active", "request", func(_ *RenewalTimingStatus, a *AutomationStatus) { a.Request = "active" }},
		{"events", "storage-capacity", "capacity", func(_ *RenewalTimingStatus, a *AutomationStatus) { a.Capacity.EventsFree = 1 }},
		{"generations", "storage-capacity", "capacity", func(_ *RenewalTimingStatus, a *AutomationStatus) { a.Capacity.GenerationsFree = 1 }},
		{"bytes", "storage-capacity", "capacity", func(_ *RenewalTimingStatus, a *AutomationStatus) { a.Capacity.BytesFree = 16383 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs, ca := s, a
			tc.edit(&cs, &ca)
			beforeS, beforeA := cs, ca
			p := timingReadiness(cs, ca, at)
			if p.CanStart || p.Reason != tc.reason || p.Recovery != tc.recovery || !reflect.DeepEqual(cs, beforeS) || !reflect.DeepEqual(ca, beforeA) {
				t.Fatal("unsafe recovery decision", p)
			}
		})
	}
	s.NextCheck = at.Add(time.Hour).Format(time.RFC3339Nano)
	s.ProviderNotBefore = at.Add(time.Hour + time.Nanosecond).Format(time.RFC3339Nano)
	p := timingReadiness(s, a, at)
	if !p.CanStart || p.Reason != "provider-wait" || p.NextCheck != s.ProviderNotBefore {
		t.Fatal("wait shortened at fractional boundary")
	}
	s.Pending, s.Blocked, s.Expired = true, true, true
	p = timingReadiness(s, a, at)
	if p.CanStart || p.Recovery != "timing" {
		t.Fatal("ended/blocked source hid safe local retirement")
	}
}
