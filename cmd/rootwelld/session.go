package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/denyfirst/rootwell/internal/account"
)

const (
	cookieName = "__Host-rootwell_session"
	// A signed-in session ends after 15 minutes without use and 8 hours at
	// most (ADR 0088).
	idleLife     = 15 * time.Minute
	absoluteLife = 8 * time.Hour
	// The phone code follows the password within five minutes; a phone being
	// confirmed during setup has fifteen.
	codeLife  = 5 * time.Minute
	setupLife = 15 * time.Minute
	// freshLife is how long a phone code lets a person show a key, delete one,
	// or change how they sign in, without being asked again.
	freshLife = 10 * time.Minute
	// maxSessions bounds the sessions kept in memory.
	maxSessions = 64
	// passkeyLife is how long a passkey challenge may be answered.
	passkeyLife = 2 * time.Minute
	// wrongCodesEnd is how many wrong codes end a session.
	wrongCodesEnd = 5
)

type stage int

const (
	// stageSetup: a setup code, a name and a password were accepted, and a
	// phone is being confirmed. Nothing is saved until it is.
	stageSetup stage = iota + 1
	// stageCode: the password was accepted, and the phone code is next.
	stageCode
	// stageReady: signed in.
	stageReady
)

type session struct {
	stage    stage
	name     string
	revision uint64
	created  time.Time
	seen     time.Time
	fresh    time.Time
	wrong    int
	// Setup and a phone replacement keep their pieces here, in memory only,
	// for the few minutes they last.
	setupCode string
	password  account.PasswordHash
	seed      string
	// A passkey ceremony under way: the challenge sent, what it is for, and
	// until when it may be answered. One answer uses it up.
	challenge      []byte
	challengeFor   string
	challengeUntil time.Time
}

func (s *session) live(now time.Time) bool {
	switch s.stage {
	case stageSetup:
		return now.Before(s.created.Add(setupLife))
	case stageCode:
		return now.Before(s.created.Add(codeLife))
	case stageReady:
		return now.Before(s.created.Add(absoluteLife)) && now.Before(s.seen.Add(idleLife))
	}
	return false
}

func (s *session) lifetime() time.Duration {
	switch s.stage {
	case stageSetup:
		return setupLife
	case stageCode:
		return codeLife
	}
	return absoluteLife
}

// sessionID reads the one session cookie. A request with two is treated as
// having none, so a cookie planted beside the real one cannot pick a session.
func sessionID(r *http.Request) ([32]byte, bool) {
	var value string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == cookieName {
			value = c.Value
			count++
		}
	}
	if count != 1 || len(value) != 43 {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(value)), true
}

// currentSession finds the request's live session and returns a copy. touch
// counts the request as use; a page asking for its status does not.
func (g *gate) currentSession(r *http.Request, touch bool) ([32]byte, session, bool) {
	id, ok := sessionID(r)
	if !ok {
		return id, session{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[id]
	now := g.now()
	if !ok || !s.live(now) {
		delete(g.sessions, id)
		return id, session{}, false
	}
	if touch && s.stage == stageReady {
		s.seen = now
	}
	return id, *s, true
}

var errTooManySessions = errors.New("too many sessions")

// issue keeps s under a new token, ending the session old (if any): a session
// gets a new token whenever it moves a stage on.
func (g *gate) issue(w http.ResponseWriter, old [32]byte, s session) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return errors.New("session could not be created")
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	id := sha256.Sum256([]byte(token))
	now := g.now()
	g.mu.Lock()
	delete(g.sessions, old)
	for key, value := range g.sessions {
		if !value.live(now) {
			delete(g.sessions, key)
		}
	}
	if len(g.sessions) >= maxSessions {
		// Full: the same account's oldest session makes room for its newest.
		// Nobody else's session is ever ended to make room.
		var oldest [32]byte
		found := false
		for key, value := range g.sessions {
			if s.name != "" && value.name == s.name && (!found || value.created.Before(g.sessions[oldest].created)) {
				oldest, found = key, true
			}
		}
		if !found {
			g.mu.Unlock()
			return errTooManySessions
		}
		delete(g.sessions, oldest)
	}
	s.created, s.seen = now, now
	g.sessions[id] = &s
	g.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", MaxAge: int(s.lifetime() / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	return nil
}

// update changes the live session id in place.
func (g *gate) update(id [32]byte, change func(*session)) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[id]
	if !ok || !s.live(g.now()) {
		return false
	}
	change(s)
	return true
}

// wrongCode counts a wrong code in a session and ends it at wrongCodesEnd.
// It reports whether the session ended.
func (g *gate) wrongCode(w http.ResponseWriter, id [32]byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[id]
	if !ok {
		return true
	}
	s.wrong++
	if s.wrong < wrongCodesEnd {
		return false
	}
	delete(g.sessions, id)
	clearCookie(w)
	return true
}

// endAccount ends every session of an account: its password, phone or
// recovery codes changed.
func (g *gate) endAccount(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, s := range g.sessions {
		if s.name == name {
			delete(g.sessions, id)
		}
	}
}

func (g *gate) end(w http.ResponseWriter, id [32]byte) {
	g.mu.Lock()
	delete(g.sessions, id)
	g.mu.Unlock()
	clearCookie(w)
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

// Sign-in limits count failures only, per account name and per source
// address; a success costs nothing (audit RW-07). After the allowed failures
// each further one doubles the wait, from one minute up to fifteen.
const (
	nameFailures   = 5
	sourceFailures = 20
	maxWait        = 15 * time.Minute
	forgetFailures = time.Hour
	maxLimitKeys   = 4096
)

type failures struct {
	count int
	last  time.Time
	until time.Time
}

type limitKey struct {
	key     string
	allowed int
}

func nameLimit(name string) limitKey { return limitKey{"name:" + name, nameFailures} }

// sourceLimit is the request's address; an IPv6 address counts by its /64,
// the block one host usually holds.
func sourceLimit(r *http.Request) limitKey {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return limitKey{"source:unknown", sourceFailures}
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is6() {
		prefix, _ := addr.Prefix(64)
		return limitKey{"source:" + prefix.String(), sourceFailures}
	}
	return limitKey{"source:" + addr.String(), sourceFailures}
}

// wait is how long the longest of keys must still wait; zero lets it through.
func (g *gate) wait(keys ...limitKey) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	var longest time.Duration
	for _, k := range keys {
		f, ok := g.failures[k.key]
		switch {
		case ok && now.Before(f.until):
			longest = max(longest, f.until.Sub(now))
		case !ok && now.Before(g.crowded):
			longest = max(longest, g.crowded.Sub(now))
		}
	}
	return longest
}

// fail counts one failure against each key.
func (g *gate) fail(keys ...limitKey) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	for _, k := range keys {
		f, ok := g.failures[k.key]
		if ok && now.Sub(f.last) >= forgetFailures && !now.Before(f.until) {
			f.count = 0
		}
		if !ok {
			if len(g.failures) >= maxLimitKeys && !g.makeRoomLocked(now) {
				// Every entry is waiting out a lock. Rather than forget someone
				// else's, every name and address not counted yet waits a minute.
				g.crowded = now.Add(time.Minute)
				continue
			}
			f = &failures{}
			g.failures[k.key] = f
		}
		f.count++
		f.last = now
		if f.count >= k.allowed {
			f.until = now.Add(min(maxWait, time.Minute<<min(f.count-k.allowed, 4)))
		}
	}
}

// makeRoomLocked forgets the entry whose last failure is oldest among those
// not waiting out a lock.
func (g *gate) makeRoomLocked(now time.Time) bool {
	var oldest string
	for key, f := range g.failures {
		if now.Before(f.until) {
			continue
		}
		if oldest == "" || f.last.Before(g.failures[oldest].last) {
			oldest = key
		}
	}
	if oldest == "" {
		return false
	}
	delete(g.failures, oldest)
	return true
}

// succeed forgets a name's failures once it signs in completely.
func (g *gate) succeed(k limitKey) {
	g.mu.Lock()
	delete(g.failures, k.key)
	g.mu.Unlock()
}

// passkeyName is the WebAuthn relying party for the request's host: its DNS
// name. Browsers allow no passkeys on an IP address.
func passkeyName(host string) (string, bool) {
	name, _, err := net.SplitHostPort(host)
	if err != nil || name == "" {
		return "", false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", false
	}
	return name, true
}
