package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTimingWatchBusyCannotShortenSpacingAndOwnerCannotChange(t *testing.T) {
	now := time.Date(2026, 10, 27, 1, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &timingWatch{owner: watchOwner("original-session"), id: strings.Repeat("ab", 16), state: "waiting", reason: "provider-wait", recovery: "none", ctx: ctx, cancel: cancel, next: now.Add(5 * time.Minute), expires: now.Add(time.Hour), last: now, started: now, checks: 1}
	g := &gate{now: func() time.Time { return now }, watch: w}
	g.deferTimingWatch(w, "busy")
	if w.next != now.Add(5*time.Minute) || w.checks != 1 {
		t.Fatal("busy shortened spacing or reset counters")
	}
	w.issued = time.Now()
	w.next = time.Time{}
	minimumWatchSpacing(w, now.Add(time.Hour))
	if w.next.Before(now.Add(time.Hour + 4*time.Minute)) {
		t.Fatal("wall-clock jump shortened monotonic spacing")
	}
	if out := g.watchSnapshot(watchOwner("another-session")); out.State != "not-running" || out.ID != "" || out.Fingerprint != "" {
		t.Fatal("authority/details shared across sessions")
	}
	g.mu.Lock()
	g.pauseWatchLocked(w, "stopped", "none")
	g.mu.Unlock()
	if w.ctx.Err() == nil || w.state != "paused" || !w.next.IsZero() {
		t.Fatal("stop retained authority")
	}
	typeOf := reflect.TypeFor[timingWatch]()
	for i := 0; i < typeOf.NumField(); i++ {
		f := typeOf.Field(i)
		for _, secret := range []string{"password", "dataKey", "signer", "credential", "installationID", "session"} {
			if strings.Contains(strings.ToLower(f.Name), strings.ToLower(secret)) {
				t.Fatal("independent unlock/custody field in watch", f.Name)
			}
		}
	}
}

func TestTimingWatchConstructorCannotExtendOrSwitchReadySession(t *testing.T) {
	owner := watchOwner("original-session")
	now := time.Now()
	base := session{inventoryReady: true, expires: now.Add(time.Hour), revision: [32]byte{1}}
	for _, mode := range []string{"missing", "setup", "no-identity", "changed-revision", "changed-expiry", "expired", "extended", "closed"} {
		g := &gate{now: func() time.Time { return now }, sessions: map[[32]byte]session{owner: base}}
		s := base
		switch mode {
		case "missing":
			delete(g.sessions, owner)
		case "setup":
			cs := base
			cs.setup = true
			g.sessions[owner] = cs
		case "no-identity":
			cs := base
			cs.inventoryReady = false
			g.sessions[owner] = cs
		case "changed-revision":
			s.revision[0] ^= 1
		case "changed-expiry":
			s.expires = s.expires.Add(time.Second)
		case "expired":
			s.expires = now
			g.sessions[owner] = s
		case "extended":
			s.expires = now.Add(13 * time.Hour)
			g.sessions[owner] = s
		case "closed":
			g.closed = true
		}
		if out, err := g.newTimingWatch(owner, s, "public-source", "Test certificate", 13); err == nil || out != nil || g.watch != nil {
			t.Fatal("invalid session got independent authority", mode)
		}
	}
}
