package renewalpolicy

import (
	"crypto/rand"
	"math/big"
	"time"
)

type Selection struct {
	Source string
	At     time.Time
}

// FallbackWindow spreads work EARLIER than the lifetime backstop (two thirds,
// or halfway for <10 days). Never assume a fixed certificate validity period.
func FallbackWindow(lifetime Window) (Window, error) {
	if !validWindow(lifetime) {
		return Window{}, ErrInvalid
	}
	span := lifetime.End.Sub(lifetime.Start)
	backstop := span / 3 * 2
	if span < 10*24*time.Hour {
		backstop = span / 2
	}
	// Sub-second lifetimes cannot support a useful bounded schedule.
	if span < time.Second {
		return Window{}, ErrInvalid
	}
	end := lifetime.Start.Add(backstop)
	return Window{Start: end.Add(-span / 24), End: end}, nil
}

// Select chooses once. The caller MUST durably bind selection and source to
// the exact certificate before scheduling; do not reroll on each status read,
// process restart or backup restore. This function grants no network authority.
// CA/provider error backoff always wins, even over an urgent ARI window.
func Select(lifetime Window, information *Information, now, notBefore time.Time) (Selection, error) {
	return selectAt(lifetime, information, now, notBefore, func(bound *big.Int) (*big.Int, error) { return rand.Int(rand.Reader, bound) })
}

func selectAt(lifetime Window, information *Information, now, notBefore time.Time, pick func(*big.Int) (*big.Int, error)) (Selection, error) {
	bad := func() (Selection, error) { return Selection{}, ErrInvalid }
	if !validWindow(lifetime) || !validTime(now) || now.Before(lifetime.Start) || !now.Before(lifetime.End) || !notBefore.IsZero() && !validTime(notBefore) || pick == nil {
		return bad()
	}
	window, err := FallbackWindow(lifetime)
	if err != nil {
		return bad()
	}
	source := "fallback"
	if information != nil {
		i := information
		if !validWindow(i.Window) || !validTime(i.CheckedAt) || i.CheckedAt.After(now) || !i.CheckedAt.Before(lifetime.End) || !validTime(i.CheckAfter) || !now.Before(i.CheckAfter) || !i.CheckAfter.After(i.CheckedAt) || i.CheckAfter.Sub(i.CheckedAt) < time.Minute || i.CheckAfter.Sub(i.CheckedAt) > 24*time.Hour || i.Window.End.After(lifetime.End) {
			return bad()
		}
		window, source = i.Window, "ari"
	}
	width := big.NewInt(int64(window.End.Sub(window.Start)))
	n, err := pick(width)
	if err != nil || n == nil || n.Sign() < 0 || n.Cmp(width) >= 0 || !n.IsInt64() {
		return bad()
	}
	at := window.Start.Add(time.Duration(n.Int64()))
	if at.Before(now) {
		at = now
	}
	if at.Before(notBefore) {
		at = notBefore
	}
	if !at.Before(lifetime.End) {
		return bad()
	}
	return Selection{Source: source, At: at.UTC()}, nil
}
