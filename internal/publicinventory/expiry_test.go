package publicinventory

import (
	"testing"
	"time"
)

func TestObserveExpiryExactBoundariesAndNoTrust(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		seconds int64
		status  string
		days    int64
	}{
		{"expired", -86401, "expired", -1},
		{"just-expired", -1, "expired", 0},
		{"equal", 0, "expired", 0},
		{"one-second", 1, "soon", 1},
		{"one-day", 86400, "soon", 1},
		{"seven-days", 7 * 86400, "soon", 7},
		{"seven-days-plus", 7*86400 + 1, "soon", 8},
		{"fourteen-days", 14 * 86400, "soon", 14},
		{"thirty-days", 30 * 86400, "soon", 30},
		{"thirty-days-plus", 30*86400 + 1, "medium", 31},
		{"ninety-days", 90 * 86400, "medium", 90},
		{"ninety-days-plus", 90*86400 + 1, "later", 91},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Record{NotBefore: now.AddDate(-1, 0, 0).Format(time.RFC3339), NotAfter: time.Unix(now.Unix()+tc.seconds, 0).UTC().Format(time.RFC3339)}
			got := ObserveExpiry(r, now)
			if got.Status != tc.status || got.DaysLeft == nil || *got.DaysLeft != tc.days {
				t.Fatalf("got %+v, want %s/%d", got, tc.status, tc.days)
			}
		})
	}
}

func TestObserveExpiryRejectsMalformedAndHandlesLongDates(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for _, dates := range [][2]string{
		{"", ""}, {"2026-10-06T12:00:00Z", "2026-10-06T12:00:00Z"},
		{"2027-01-01T00:00:00Z", "2026-01-01T00:00:00Z"},
		{"2026-02-30T00:00:00Z", "2027-01-01T00:00:00Z"},
		{"2026-01-01T00:00:00+00:00", "2027-01-01T00:00:00Z"},
		{"2026-01-01T00:00:00Z", "2027-01-01T00:00:00.1Z"},
		{"secret-date", "secret-date"},
	} {
		got := ObserveExpiry(Record{NotBefore: dates[0], NotAfter: dates[1]}, now)
		if got.Status != "invalid" || got.DaysLeft != nil {
			t.Fatal("invalid date became an expiry verdict")
		}
	}
	r := Record{NotBefore: "0000-01-01T00:00:00Z", NotAfter: "9999-12-31T23:59:59Z"}
	got := ObserveExpiry(r, now)
	want := (time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC).Unix() - now.Unix() + 86399) / 86400
	if got.Status != "later" || got.DaysLeft == nil || *got.DaysLeft != want {
		t.Fatal("long date duration overflow")
	}
	r.NotBefore = "2027-01-01T00:00:00Z"
	if got := ObserveExpiry(r, now); got.Status != "future" {
		t.Fatal("not-yet-valid certificate treated as current")
	}
	for _, year := range []int{-1, 10000} {
		if got := ObserveExpiry(r, time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)); got.Status != "invalid" {
			t.Fatal("unrepresentable server clock accepted")
		}
	}
}
