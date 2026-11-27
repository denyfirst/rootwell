package alerts

import (
	"testing"
	"time"
)

func at(days float64, now time.Time) time.Time { return now.Add(time.Duration(days * float64(day))) }

func TestEachStepIsSentOnceAndOnlyTheNearest(t *testing.T) {
	now := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	shop := Certificate{Fingerprint: "AA", Name: "shop.test", NotAfter: at(40, now)}
	sent := Sent{}
	steps := []struct {
		days float64
		want int // -1 for nothing due
	}{
		{40, -1}, {30.5, -1}, {30, 30}, {29, -1}, {14, 14}, {13.2, -1}, {8, -1}, {6.5, 7}, {1, -1}, {0, 0}, {-3, -1},
	}
	for _, s := range steps {
		when := shop.NotAfter.Add(-time.Duration(s.days * float64(day)))
		due := Due([]Certificate{shop}, sent, when)
		if s.want < 0 {
			if len(due) != 0 {
				t.Fatalf("%v days left: %+v is due", s.days, due)
			}
			continue
		}
		if len(due) != 1 || due[0].Step != s.want {
			t.Fatalf("%v days left: want step %d, got %+v", s.days, s.want, due)
		}
		sent = Remember(sent, due, []Certificate{shop})
	}
	// Added late, with five days left: one alert, the nearest step.
	late := Certificate{Fingerprint: "BB", NotAfter: at(5, now)}
	if due := Due([]Certificate{late}, Sent{}, now); len(due) != 1 || due[0].Step != 7 || due[0].DaysLeft != 5 {
		t.Fatalf("a late certificate: %+v", due)
	}
	// Ended before Rootwell ever saw it: one alert, the end.
	gone := Certificate{Fingerprint: "CC", NotAfter: at(-10, now)}
	if due := Due([]Certificate{gone}, Sent{}, now); len(due) != 1 || due[0].Step != 0 || due[0].DaysLeft != 0 {
		t.Fatalf("an ended certificate: %+v", due)
	}
}

func TestANewEndDateStartsAgainAndTheRecordStaysSmall(t *testing.T) {
	now := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	c := Certificate{Fingerprint: "AA", NotAfter: at(6, now)}
	sent := Remember(Sent{}, Due([]Certificate{c}, Sent{}, now), []Certificate{c})
	if sent["AA"].Step != 7 {
		t.Fatalf("recorded %+v", sent)
	}
	c.NotAfter = at(20, now)
	if due := Due([]Certificate{c}, sent, now); len(due) != 1 || due[0].Step != 30 {
		t.Fatalf("a moved end date did not start again: %+v", due)
	}
	other := Certificate{Fingerprint: "BB", NotAfter: at(3, now)}
	sent = Remember(sent, nil, []Certificate{other})
	if _, kept := sent["AA"]; kept || len(sent) != 0 {
		t.Fatalf("a certificate no longer listed is remembered: %+v", sent)
	}
}

func TestDueIsSoonestFirst(t *testing.T) {
	now := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	due := Due([]Certificate{{Fingerprint: "late", NotAfter: at(12, now)}, {Fingerprint: "soon", NotAfter: at(2, now)}, {Fingerprint: "far", NotAfter: at(90, now)}}, Sent{}, now)
	if len(due) != 2 || due[0].Certificate.Fingerprint != "soon" || due[1].Certificate.Fingerprint != "late" {
		t.Fatalf("order: %+v", due)
	}
}
