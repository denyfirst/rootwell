// Package providerretry supplies bounded retry policy, never a scheduler or
// authority to repeat an irreversible request. A caller must durably retain
// state before I/O and keep its existing exact-operation authorization.
package providerretry

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

const MaxAttempts = 6
const MaxProviderWait = 7 * 24 * time.Hour

var ErrInvalid = errors.New("retry policy unavailable")

type State struct {
	Attempts  int    `json:"attempts"`
	LastAt    string `json:"last_at"`
	NotBefore string `json:"not_before"`
}

// Hint contains no raw response, URL, error detail, credentials or headers.
type Hint struct {
	NotBefore time.Time
	Blocked   bool
}

// Failure's fixed text cannot reflect a provider's body or request secrets.
type Failure struct{ Hint Hint }

func (*Failure) Error() string { return "provider operation not confirmed" }

func canonical(value string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02T15:04:05Z", value)
	return t, err == nil && t.Year() >= 2020 && t.Year() <= 2100 && t.UTC().Format("2006-01-02T15:04:05Z") == value
}
func Valid(s State) bool {
	if s.Attempts == 0 {
		return s.LastAt == "" && s.NotBefore == ""
	}
	last, ok := canonical(s.LastAt)
	next, valid := canonical(s.NotBefore)
	return s.Attempts > 0 && s.Attempts <= MaxAttempts && ok && valid && next.After(last) && next.Sub(last) <= MaxProviderWait
}
func Ready(s State, now time.Time) bool {
	if !Valid(s) || now.Year() < 2020 || now.Year() > 2100 || s.Attempts >= MaxAttempts {
		return false
	}
	if s.Attempts == 0 {
		return true
	}
	last, _ := canonical(s.LastAt)
	next, _ := canonical(s.NotBefore)
	return !now.Before(last) && !now.Before(next)
}

// Begin reserves an attempt BEFORE transmission. Crash/uncertainty consumes it.
// Jitter is in whole seconds [0,30], chosen randomly by the trusted caller.
// This state never says a create/finalize/challenge mutation may be replayed.
func Begin(s State, now time.Time, jitter int) (State, error) {
	if !Ready(s, now) || jitter < 0 || jitter > 30 {
		return State{}, ErrInvalid
	}
	now = now.UTC()
	delay := 30*time.Second*time.Duration(1<<s.Attempts) + time.Duration(jitter)*time.Second
	nextAt := now.Add(delay)
	if nextAt.Nanosecond() != 0 {
		nextAt = nextAt.Truncate(time.Second).Add(time.Second)
	}
	next := State{Attempts: s.Attempts + 1, LastAt: now.Format("2006-01-02T15:04:05Z"), NotBefore: nextAt.Format("2006-01-02T15:04:05Z")}
	if !Valid(next) {
		return State{}, ErrInvalid
	}
	return next, nil
}

// Apply carries a longer authenticated provider wait into the SAME intent.
// Invalid/too-long hints refuse, never clamp down to an earlier retry time.
func Apply(s State, h Hint) (State, error) {
	if !Valid(s) || s.Attempts == 0 || h.Blocked {
		return State{}, ErrInvalid
	}
	if h.NotBefore.IsZero() {
		return s, nil
	}
	last, _ := canonical(s.LastAt)
	next, _ := canonical(s.NotBefore)
	bound := h.NotBefore.UTC()
	// Round up fractional hints; never retry earlier than a provider requested.
	if bound.Nanosecond() != 0 {
		bound = bound.Truncate(time.Second).Add(time.Second)
	}
	if bound.Year() < 2020 || bound.Year() > 2100 || bound.Sub(last) > MaxProviderWait {
		return State{}, ErrInvalid
	}
	if bound.After(next) {
		s.NotBefore = bound.Format("2006-01-02T15:04:05Z")
	}
	return s, nil
}

// RetryAfter accepts exactly one bounded HTTP delta-seconds or IMF-fixdate.
// Missing is a local-backoff hint; malformed/duplicates/oversize block attempts.
// It deliberately has no net/http import or authority to fetch a header URL.
func RetryAfter(values []string, now time.Time) Hint {
	if len(values) == 0 {
		return Hint{}
	}
	bad := Hint{Blocked: true}
	if len(values) != 1 || len(values[0]) < 1 || len(values[0]) > 64 || now.Year() < 2020 || now.Year() > 2100 {
		return bad
	}
	value := values[0]
	digits := true
	for _, c := range value {
		if c < '0' || c > '9' {
			digits = false
			break
		}
	}
	if digits {
		seconds, err := strconv.ParseUint(value, 10, 32)
		if err != nil || seconds > uint64(MaxProviderWait/time.Second) {
			return bad
		}
		return Hint{NotBefore: now.Add(time.Duration(seconds) * time.Second)}
	}
	if strings.TrimSpace(value) != value {
		return bad
	}
	t, err := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", value)
	if err != nil || t.Format("Mon, 02 Jan 2006 15:04:05 GMT") != value || t.Year() < 2020 || t.Year() > 2100 || t.Sub(now) > MaxProviderWait {
		return bad
	}
	return Hint{NotBefore: t}
}
