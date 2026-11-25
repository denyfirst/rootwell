package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// callFrom is call from a given address, with any cookies.
func callFrom(g *gate, source, method, route, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://"+localHost+route, strings.NewReader(body))
	r.RemoteAddr = source
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPost || method == http.MethodDelete {
		r.Header.Set("Origin", "https://"+localHost)
		r.Header.Set("X-Rootwell-Request", "1")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

// idOf is the session ID a session cookie names.
func idOf(c *http.Cookie) [32]byte { return sha256.Sum256([]byte(c.Value)) }

func deviceCookieOf(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == deviceCookie && c.MaxAge > 0 {
			return c
		}
	}
	return nil
}

func passwordBody(password string) string {
	return `{"name":"` + testName + `","password":"` + password + `"}`
}

// Wrong codes sent all at once are counted one by one: no more than five are
// ever checked, against the session and against the name.
func TestCodeGuessesSentTogetherAreCountedOneByOne(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	c := e.passwordStep(t, testPassword)
	const guesses = 24
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	checked := 0
	for range guesses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			w := call(e.g, "POST", "/api/session/code", `{"code":"000000"}`, c)
			if w.Code == http.StatusUnauthorized && strings.HasPrefix(w.Body.String(), "That code does not match.") {
				mu.Lock()
				checked++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	e.g.mu.Lock()
	name := e.g.failures[nameLimit(testName).key]
	e.g.mu.Unlock()
	if checked >= wrongCodesEnd || name == nil || name.count > nameFailures {
		t.Fatalf("%d wrong codes answered as checked; the name counted %v", checked, name)
	}
	if status(t, e.g, c) != nil {
		t.Fatal("the session outlived five wrong codes")
	}
	if w := call(e.g, "POST", "/api/session/code", `{"code":"`+e.code(t)+`"}`, c); w.Code != http.StatusUnauthorized {
		t.Fatalf("the right code after five wrong ones: %d", w.Code)
	}
}

// A session that wrong codes ended is never brought back by a right code that
// was already on its way.
func TestARightCodeDoesNotReviveAnEndedSession(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	c := e.passwordStep(t, testPassword)
	id := idOf(c)
	e.g.mu.Lock()
	e.g.sessions[id].wrong = wrongCodesEnd
	e.g.mu.Unlock()
	if w := call(e.g, "POST", "/api/session/code", `{"code":"`+e.code(t)+`"}`, c); w.Code != http.StatusUnauthorized {
		t.Fatalf("a right code on a spent session: %d", w.Code)
	}
	// Wrong codes sent together end it while a right one is checked: the
	// right one cannot move it on.
	if !e.g.spent(httptest.NewRecorder(), id) {
		t.Fatal("five wrong codes did not end the session")
	}
	if err := e.g.promote(httptest.NewRecorder(), id, session{stage: stageReady, name: testName}); !errors.Is(err, errSessionGone) {
		t.Fatalf("promote from an ended session: %v", err)
	}
	if status(t, e.g, c) != nil {
		t.Fatal("the ended session came back")
	}
}

// Once a wait ends, the right password and code sign in at once: the
// attempt that succeeded leaves no wait behind.
func TestTheOwnerSignsInAsSoonAsAWaitEnds(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	for range nameFailures {
		callFrom(e.g, "198.51.100.7:1", "POST", "/api/session", passwordBody("not the password at all"))
	}
	if w := callFrom(e.g, "198.51.100.7:1", "POST", "/api/session", passwordBody(testPassword)); w.Code != http.StatusTooManyRequests {
		t.Fatalf("during the wait: %d", w.Code)
	}
	e.clock.add(time.Minute)
	w := callFrom(e.g, "198.51.100.7:1", "POST", "/api/session", passwordBody(testPassword))
	if w.Code != http.StatusNoContent {
		t.Fatalf("the password after the wait: %d", w.Code)
	}
	if w := callFrom(e.g, "198.51.100.7:1", "POST", "/api/session/code", `{"code":"`+e.code(t)+`"}`, sessionCookie(t, w)); w.Code != http.StatusNoContent {
		t.Fatalf("the code after the wait: %d %s", w.Code, w.Body)
	}
}

// A browser that signed in before is not locked out by failures elsewhere:
// not by guesses at the name from any address, nor by failures from its own
// address, which everyone on the server itself shares.
func TestAKnownDeviceIsNotLockedOutByOthers(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	const owner, other = "127.0.0.1:50000", "198.51.100.7:1"
	w := callFrom(e.g, owner, "POST", "/api/session", passwordBody(testPassword))
	if w.Code != http.StatusNoContent || deviceCookieOf(w) != nil {
		t.Fatalf("the password step: %d, device cookie %v", w.Code, deviceCookieOf(w))
	}
	w = callFrom(e.g, owner, "POST", "/api/session/code", `{"code":"`+e.code(t)+`"}`, sessionCookie(t, w))
	first := deviceCookieOf(w)
	if w.Code != http.StatusNoContent || first == nil {
		t.Fatalf("the code step: %d, no device cookie", w.Code)
	}
	if !first.HttpOnly || !first.Secure || first.SameSite != http.SameSiteStrictMode || first.Path != "/" || first.Domain != "" ||
		first.MaxAge != 30*24*60*60 || len(first.Value) != 43 {
		t.Fatalf("device cookie %+v", first)
	}
	// Someone guesses at the name from elsewhere, and others on the server
	// fail from its own address.
	for range nameFailures {
		callFrom(e.g, other, "POST", "/api/session", passwordBody("not the password at all"))
	}
	for i := range sourceFailures {
		callFrom(e.g, "127.0.0.1:1", "POST", "/api/session", `{"name":"`+fmt.Sprintf("n%d", i)+`","password":"not the password at all"}`)
	}
	if w := callFrom(e.g, owner, "POST", "/api/session", passwordBody(testPassword)); w.Code != http.StatusTooManyRequests {
		t.Fatalf("a browser without the device cookie: %d", w.Code)
	}
	w = callFrom(e.g, owner, "POST", "/api/session", passwordBody(testPassword), first)
	if w.Code != http.StatusNoContent {
		t.Fatalf("the known device's password: %d", w.Code)
	}
	w = callFrom(e.g, owner, "POST", "/api/session/code", `{"code":"`+e.code(t)+`"}`, sessionCookie(t, w), first)
	second := deviceCookieOf(w)
	if w.Code != http.StatusNoContent || second == nil || second.Value == first.Value {
		t.Fatalf("the known device's code: %d, device cookie %v", w.Code, second)
	}
	if !e.g.accounts.KnownDevice(testName, sha256.Sum256([]byte(second.Value))) {
		t.Fatal("the account does not know the new device cookie")
	}
	// Each sign-in replaces the device cookie: the old one is forgotten.
	if w := callFrom(e.g, owner, "POST", "/api/session", passwordBody(testPassword), first); w.Code != http.StatusTooManyRequests {
		t.Fatalf("the replaced device cookie: %d", w.Code)
	}
	// A device cookie of the right shape that the account never saw is no
	// help, and two device cookies count as none.
	forged := &http.Cookie{Name: deviceCookie, Value: strings.Repeat("A", 43)}
	if w := callFrom(e.g, owner, "POST", "/api/session", passwordBody(testPassword), forged); w.Code != http.StatusTooManyRequests {
		t.Fatalf("an unknown device cookie: %d", w.Code)
	}
	if w := callFrom(e.g, owner, "POST", "/api/session", passwordBody(testPassword), forged, second); w.Code != http.StatusTooManyRequests {
		t.Fatalf("two device cookies: %d", w.Code)
	}
	// A known device's own failures still count, against it alone.
	for i := range nameFailures {
		if w := callFrom(e.g, owner, "POST", "/api/session", passwordBody("not the password at all"), second); w.Code != http.StatusUnauthorized {
			t.Fatalf("the device's failure %d: %d", i, w.Code)
		}
	}
	if w := callFrom(e.g, owner, "POST", "/api/session", passwordBody(testPassword), second); w.Code != http.StatusTooManyRequests {
		t.Fatalf("the device after its own five failures: %d", w.Code)
	}
}

// Wrong setup codes count against their source alone: nobody can keep the
// owner from setting up or recovering by guessing from elsewhere.
func TestSetupGuessesCountOnlyAgainstTheirSource(t *testing.T) {
	e := newTestEnv(t)
	code, _, err := e.g.accounts.NewSetupCode("")
	if err != nil {
		t.Fatal(err)
	}
	wrong := `{"code":"aaaaaa-bbbbbb-cccccc-dddddd","name":"ada","password":"` + testPassword + `"}`
	for range sourceFailures {
		callFrom(e.g, "198.51.100.7:1", "POST", "/api/setup", wrong)
	}
	if w := callFrom(e.g, "198.51.100.7:1", "POST", "/api/setup", wrong); w.Code != http.StatusTooManyRequests {
		t.Fatalf("the guessing address: %d", w.Code)
	}
	if w := callFrom(e.g, "192.0.2.1:1", "POST", "/api/setup", `{"code":"`+code+`","name":"ada","password":"`+testPassword+`"}`); w.Code != http.StatusOK {
		t.Fatalf("the owner from another address: %d %s", w.Code, w.Body)
	}
}

// A fresh code moves the session to a new token and keeps its start, so the
// eight hours still count from the sign-in.
func TestAFreshCodeMovesTheSessionToANewToken(t *testing.T) {
	g, c, e := readyGate(t)
	g.mu.Lock()
	created := g.sessions[idOf(c)].created
	g.mu.Unlock()
	e.clock.add(freshLife)
	w := call(g, "POST", "/api/fresh", `{"code":"`+e.code(t)+`"}`, c)
	if w.Code != http.StatusNoContent {
		t.Fatalf("a fresh code: %d", w.Code)
	}
	next := sessionCookie(t, w)
	if next.Value == c.Value || status(t, g, c) != nil {
		t.Fatal("the old token still works after a fresh code")
	}
	if got := status(t, g, next); got["stage"] != "ready" || got["fresh"] != true {
		t.Fatalf("after a fresh code: %v", got)
	}
	g.mu.Lock()
	kept := g.sessions[idOf(next)].created
	g.mu.Unlock()
	if !kept.Equal(created) {
		t.Fatalf("the session start moved from %v to %v", created, kept)
	}
}

// Wrong codes from a new phone count like any other: five end the session,
// and the old phone stays.
func TestFiveWrongNewPhoneCodesEndTheSession(t *testing.T) {
	g, c, e := readyGate(t)
	if w := call(g, "POST", "/api/phone", `{}`, c); w.Code != http.StatusOK {
		t.Fatalf("new phone: %d", w.Code)
	}
	for i := range wrongCodesEnd - 1 {
		if w := call(g, "POST", "/api/phone/confirm", `{"code":"000000"}`, c); w.Code != http.StatusUnauthorized || status(t, g, c) == nil {
			t.Fatalf("wrong code %d: %d, or the session ended early", i, w.Code)
		}
	}
	if w := call(g, "POST", "/api/phone/confirm", `{"code":"000000"}`, c); w.Code != http.StatusUnauthorized || status(t, g, c) != nil {
		t.Fatalf("the fifth wrong code: %d, and the session is still there", w.Code)
	}
	c = e.signIn(t)
	if status(t, g, c) == nil {
		t.Fatal("the old phone no longer signs in")
	}
}
