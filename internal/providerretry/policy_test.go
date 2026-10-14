package providerretry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRetryBudgetIntentBackoffProviderWaitAndExhaustion(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	var s State
	for attempt := 0; attempt < MaxAttempts; attempt++ {
		if !Ready(s, now) {
			t.Fatal("legitimate next attempt refused")
		}
		next, err := Begin(s, now, 7)
		if err != nil || next.Attempts != attempt+1 || !Valid(next) || Ready(next, now) {
			t.Fatal("intent/backoff missing")
		}
		at, _ := canonical(next.NotBefore)
		if at.Sub(now) != 30*time.Second*time.Duration(1<<attempt)+7*time.Second {
			t.Fatal("backoff not exponential and bounded")
		}
		if Ready(next, now.Add(-time.Second)) || Ready(next, at.Add(-time.Nanosecond)) {
			t.Fatal("early/backwards attempt allowed")
		}
		roundtrip, _ := json.Marshal(next)
		var restored State
		if json.Unmarshal(roundtrip, &restored) != nil || restored != next {
			t.Fatal("state cannot be durably retained")
		}
		s = restored
		now = at
	}
	if Ready(s, now.Add(MaxProviderWait)) {
		t.Fatal("exhausted attempts silently reset")
	}
	if next, err := Begin(s, now, 0); err == nil || next != (State{}) {
		t.Fatal("exhausted intent exposed partial state")
	}
	initial, _ := Begin(State{}, now, 0)
	h := RetryAfter([]string{"3600"}, now)
	longer, err := Apply(initial, h)
	if err != nil || longer.NotBefore != now.Add(time.Hour).Format("2006-01-02T15:04:05Z") || Ready(longer, now.Add(59*time.Minute)) {
		t.Fatal("provider wait was shortened")
	}
	shorter, err := Apply(longer, RetryAfter([]string{"0"}, now))
	if err != nil || shorter != longer {
		t.Fatal("zero provider hint bypassed local wait")
	}
}

func TestRetryPolicyRejectsMalformedClockHintsAndPartialState(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	for _, values := range [][]string{{""}, {"1", "1"}, {"-1"}, {"1.5"}, {" 20"}, {"999999999999999999999999"}, {"604801"}, {"https://evil.invalid"}, {strings.Repeat("x", 65)}, {"Wed, 13 Oct 2026 01:00:00 GMT"}} {
		if !RetryAfter(values, now).Blocked {
			t.Fatal("malformed retry hint accepted")
		}
	}
	valid := "Tue, 13 Oct 2026 01:00:00 GMT"
	if h := RetryAfter([]string{valid}, now); h.Blocked || !h.NotBefore.Equal(now.Add(time.Hour)) {
		t.Fatal("HTTP date refused")
	}
	for _, s := range []State{{Attempts: 1}, {Attempts: -1}, {Attempts: 7}, {Attempts: 0, LastAt: "secret-sentinel"}, {Attempts: 1, LastAt: "2026-02-30T00:00:00Z", NotBefore: "2026-03-01T00:00:00Z"}} {
		if Valid(s) || Ready(s, now) {
			t.Fatal("malformed persisted retry state accepted")
		}
		if next, err := Begin(s, now, 0); err == nil || next != (State{}) {
			t.Fatal("invalid state exposed intent")
		}
	}
	s, _ := Begin(State{}, now, 0)
	for _, h := range []Hint{{Blocked: true}, {NotBefore: now.Add(MaxProviderWait + time.Second)}} {
		if next, err := Apply(s, h); err == nil || next != (State{}) {
			t.Fatal("blocked/too-long hint was clamped or ignored")
		}
	}
	for _, jitter := range []int{-1, 31} {
		if next, err := Begin(State{}, now, jitter); err == nil || next != (State{}) {
			t.Fatal("unsafe jitter accepted")
		}
	}
}

func TestRetryDelayRoundsUpAndRejectsYearOverflow(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 900_000_000, time.UTC)
	s, err := Begin(State{}, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := canonical(s.NotBefore)
	if next.Sub(now) < 30*time.Second || Ready(s, now.Add(30*time.Second-time.Nanosecond)) {
		t.Fatal("fractional clock shortened local backoff")
	}
	if s, err := Begin(State{}, time.Date(2100, 12, 31, 23, 59, 59, 0, time.UTC), 0); err == nil || s != (State{}) {
		t.Fatal("clock overflow exposed invalid intent")
	}
}

func FuzzProviderRetryAfter(f *testing.F) {
	f.Add("30")
	f.Add("Tue, 13 Oct 2026 01:00:00 GMT")
	f.Add("secret-sentinel")
	f.Fuzz(func(t *testing.T, value string) {
		now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
		h := RetryAfter([]string{value}, now)
		if !h.Blocked && !h.NotBefore.IsZero() && h.NotBefore.Sub(now) > MaxProviderWait {
			t.Fatal("unbounded provider wait")
		}
	})
}
