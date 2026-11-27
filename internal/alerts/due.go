// Package alerts tells a person, by e-mail or Telegram, when a saved
// certificate comes close to its end: 30, 14 and 7 days before, and on the
// day it ends. Each step is sent once per certificate. This file decides what
// is due; it sends nothing and reads no clock of its own.
package alerts

import (
	"slices"
	"strings"
	"time"
)

// Steps are the days before the end at which an alert goes out. 0 is the end
// itself: the day a certificate expires, or any day after it was missed.
var Steps = []int{30, 14, 7, 0}

const day = 24 * time.Hour

// Certificate is what an alert says about one saved certificate.
type Certificate struct {
	Fingerprint string
	Name        string
	NotAfter    time.Time
	Places      []string
	Owner       string
}

// Alert is one message due now.
type Alert struct {
	Certificate Certificate
	// Step is the step reached: 30, 14, 7 or 0.
	Step int
	// DaysLeft counts whole days to the end, rounded up; 0 or less is ended.
	DaysLeft int
}

// Sent remembers, per certificate fingerprint, the last step an alert went
// out for, and the end date it was about. A certificate whose end moved, such
// as one that was renewed in place, starts again.
type Sent map[string]SentStep

// SentStep is one certificate's last alert.
type SentStep struct {
	Step     int       `json:"step"`
	NotAfter time.Time `json:"not_after"`
}

// daysLeft rounds up: 13 days and an hour left is 14.
func daysLeft(notAfter, now time.Time) int {
	left := notAfter.Sub(now)
	if left <= 0 {
		return 0
	}
	return int((left + day - 1) / day)
}

// step is the smallest step a certificate has reached, or -1 when it has
// more than 30 days left.
func step(notAfter, now time.Time) int {
	left := daysLeft(notAfter, now)
	if !now.Before(notAfter) {
		return 0
	}
	reached := -1
	for _, s := range Steps {
		if s > 0 && left <= s {
			reached = s
		}
	}
	return reached
}

// Due lists the alerts to send now, soonest end first: one per certificate
// that reached a step it has not been told about. Only the nearest step is
// sent: a certificate added with 5 days left gets the 7-day alert, not three.
func Due(certificates []Certificate, sent Sent, now time.Time) []Alert {
	var due []Alert
	for _, c := range certificates {
		reached := step(c.NotAfter, now)
		if reached < 0 {
			continue
		}
		if last, ok := sent[c.Fingerprint]; ok && last.NotAfter.Equal(c.NotAfter) && last.Step <= reached {
			continue
		}
		due = append(due, Alert{Certificate: c, Step: reached, DaysLeft: daysLeft(c.NotAfter, now)})
	}
	slices.SortFunc(due, func(a, b Alert) int {
		if c := a.Certificate.NotAfter.Compare(b.Certificate.NotAfter); c != 0 {
			return c
		}
		return strings.Compare(a.Certificate.Fingerprint, b.Certificate.Fingerprint)
	})
	return due
}

// Remember records that alerts went out, and forgets certificates that are
// no longer listed, so the record never grows past the list.
func Remember(sent Sent, delivered []Alert, listed []Certificate) Sent {
	out := Sent{}
	keep := map[string]bool{}
	for _, c := range listed {
		keep[c.Fingerprint] = true
	}
	for fingerprint, last := range sent {
		if keep[fingerprint] {
			out[fingerprint] = last
		}
	}
	for _, a := range delivered {
		out[a.Certificate.Fingerprint] = SentStep{Step: a.Step, NotAfter: a.Certificate.NotAfter}
	}
	return out
}
