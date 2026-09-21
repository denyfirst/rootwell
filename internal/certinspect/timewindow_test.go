package certinspect

import (
	"math"
	"testing"
	"time"
)

func TestEvaluateTimeWindow(t *testing.T) {
	start := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)
	tests := []struct {
		name        string
		notBefore   time.Time
		notAfter    time.Time
		now         time.Time
		wantStatus  TimeWindowStatus
		wantStart   *int64
		wantExpiry  *int64
		wantExpired *int64
	}{
		{name: "before", notBefore: start, notAfter: end, now: start.Add(-time.Second), wantStatus: TimeWindowNotYetValid, wantStart: secondsPointer(1)},
		{name: "start inclusive", notBefore: start, notAfter: end, now: start, wantStatus: TimeWindowWithin, wantExpiry: secondsPointer(172800)},
		{name: "inside", notBefore: start, notAfter: end, now: start.Add(24 * time.Hour), wantStatus: TimeWindowWithin, wantExpiry: secondsPointer(86400)},
		{name: "end inclusive", notBefore: start, notAfter: end, now: end, wantStatus: TimeWindowWithin, wantExpiry: secondsPointer(0)},
		{name: "after", notBefore: start, notAfter: end, now: end.Add(time.Second), wantStatus: TimeWindowExpired, wantExpired: secondsPointer(1)},
		{name: "invalid range", notBefore: end, notAfter: start, now: start, wantStatus: TimeWindowInvalidRange},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := EvaluateTimeWindow(test.notBefore, test.notAfter, test.now)
			if got.Status != test.wantStatus {
				t.Errorf("Status = %q, want %q", got.Status, test.wantStatus)
			}
			if !equalInt64Pointers(got.SecondsUntilStart, test.wantStart) {
				t.Errorf("SecondsUntilStart = %v, want %v", pointerValue(got.SecondsUntilStart), pointerValue(test.wantStart))
			}
			if !equalInt64Pointers(got.SecondsUntilExpiry, test.wantExpiry) {
				t.Errorf("SecondsUntilExpiry = %v, want %v", pointerValue(got.SecondsUntilExpiry), pointerValue(test.wantExpiry))
			}
			if !equalInt64Pointers(got.SecondsSinceExpiry, test.wantExpired) {
				t.Errorf("SecondsSinceExpiry = %v, want %v", pointerValue(got.SecondsSinceExpiry), pointerValue(test.wantExpired))
			}
			if !got.EvaluatedAt.Equal(test.now) || got.EvaluatedAt.Location() != time.UTC {
				t.Errorf("EvaluatedAt = %v, want UTC %v", got.EvaluatedAt, test.now)
			}
		})
	}
}

func TestEvaluateTimeWindowUsesInstantNotLocation(t *testing.T) {
	location := time.FixedZone("test-zone", 4*60*60)
	now := time.Date(2026, 9, 21, 14, 0, 0, 0, location)
	start := time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC)
	end := time.Date(2026, 9, 21, 11, 0, 0, 0, time.UTC)

	got := EvaluateTimeWindow(start, end, now)
	if got.Status != TimeWindowWithin {
		t.Fatalf("Status = %q, want %q", got.Status, TimeWindowWithin)
	}
	if got.SecondsUntilExpiry == nil || *got.SecondsUntilExpiry != 3600 {
		t.Fatalf("SecondsUntilExpiry = %v, want 3600", pointerValue(got.SecondsUntilExpiry))
	}
}

func TestEvaluateTimeWindowSaturatesExtremeDistance(t *testing.T) {
	start := time.Unix(math.MinInt64, 0)
	end := time.Unix(math.MaxInt64, 0)
	if got := secondsBetween(start, end); got != math.MaxInt64 {
		t.Fatalf("secondsBetween() = %d, want saturation at MaxInt64", got)
	}
}

func FuzzEvaluateTimeWindow(f *testing.F) {
	f.Add(int64(0), int64(1), int64(0))
	f.Add(int64(10), int64(20), int64(15))
	f.Add(int64(20), int64(10), int64(15))
	f.Add(int64(math.MinInt64), int64(math.MaxInt64), int64(0))

	f.Fuzz(func(t *testing.T, startSeconds, endSeconds, nowSeconds int64) {
		result := EvaluateTimeWindow(time.Unix(startSeconds, 0), time.Unix(endSeconds, 0), time.Unix(nowSeconds, 0))
		setValues := 0
		for _, value := range []*int64{result.SecondsUntilStart, result.SecondsUntilExpiry, result.SecondsSinceExpiry} {
			if value != nil {
				setValues++
				if *value < 0 {
					t.Fatalf("relative seconds = %d, want non-negative", *value)
				}
			}
		}
		if result.Status == TimeWindowInvalidRange {
			if setValues != 0 {
				t.Fatalf("invalid range has %d relative values, want zero", setValues)
			}
			return
		}
		if setValues != 1 {
			t.Fatalf("status %q has %d relative values, want one", result.Status, setValues)
		}
	})
}

func secondsPointer(value int64) *int64 {
	return &value
}

func equalInt64Pointers(left, right *int64) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func pointerValue(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}
