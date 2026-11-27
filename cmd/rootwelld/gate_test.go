package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 fixes HMAC-SHA1; the tests compute phone codes independently.
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/account"
	"github.com/denyfirst/rootwell/internal/servingstore"
	"github.com/denyfirst/rootwell/internal/vault"
)

const (
	testName         = "ada"
	testPassword     = "an account password for testing"
	nextTestPassword = "a different long test password"
)

type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.at = c.at.Add(d)
	c.mu.Unlock()
}

// testEnv is a gate on its own vault, with a clock the test moves.
type testEnv struct {
	g        *gate
	v        *vault.Store
	dir      string
	key      []byte
	assets   string
	serving  servingstore.Serving
	clock    *testClock
	seed     string
	recovery []string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	if !custody() {
		t.Skip("the vault opens only in a private Linux directory")
	}
	e := &testEnv{dir: t.TempDir(), assets: testWorkbenchAssets(t),
		clock: &testClock{at: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}}
	if err := os.Chmod(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var err error
	if e.key, err = vault.NewInstanceKey(); err != nil {
		t.Fatal(err)
	}
	if e.v, err = vault.Create(e.dir, e.key); err != nil {
		t.Fatal(err)
	}
	// The names a person would add for the LAN, besides this host's own.
	if e.serving, err = servingstore.SetNames(e.v, []string{"rootwell.lan", "192.0.2.10"}, e.clock.now()); err != nil {
		t.Fatal(err)
	}
	if e.g, err = newGate(e.v, e.assets, e.serving); err != nil {
		t.Fatal(err)
	}
	e.g.now = e.clock.now
	t.Cleanup(func() {
		_ = e.g.Close()
		_ = e.v.Close()
	})
	return e
}

// reopen closes the gate and the vault and opens them again, as a restart
// does: sessions are gone, the vault is not.
func (e *testEnv) reopen(t *testing.T) {
	t.Helper()
	_ = e.g.Close()
	if err := e.v.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	if e.v, err = vault.Open(e.dir, e.key); err != nil {
		t.Fatal(err)
	}
	if e.g, err = newGate(e.v, e.assets, e.serving); err != nil {
		t.Fatal(err)
	}
	e.g.now = e.clock.now
}

// withAccount makes the test account the way the setup page does, straight
// through the store.
func (e *testEnv) withAccount(t *testing.T) *testEnv {
	t.Helper()
	code, _, err := e.g.accounts.NewSetupCode("")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := account.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if e.seed, err = account.NewSeed(); err != nil {
		t.Fatal(err)
	}
	if e.recovery, _, err = e.g.accounts.FinishSetup(code, testName, hash, e.seed, e.clock.now().Unix()/30); err != nil {
		t.Fatal(err)
	}
	return e
}

// phoneCode is RFC 6238, computed apart from the code under test.
func phoneCode(t *testing.T, seed string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
	if err != nil {
		t.Fatal(err)
	}
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}

// code moves to the next 30-second step and returns the phone's code there.
func (e *testEnv) code(t *testing.T) string {
	t.Helper()
	e.clock.add(30 * time.Second)
	return phoneCode(t, e.seed, e.clock.now())
}

func (e *testEnv) passwordStep(t *testing.T, password string) *http.Cookie {
	t.Helper()
	w := call(e.g, "POST", "/api/session", `{"name":"`+testName+`","password":"`+password+`"}`, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("password step: %d %s", w.Code, w.Body)
	}
	return sessionCookie(t, w)
}

// signIn signs in with the password and a phone code.
func (e *testEnv) signIn(t *testing.T) *http.Cookie {
	t.Helper()
	c := e.passwordStep(t, testPassword)
	w := call(e.g, "POST", "/api/session/code", `{"code":"`+e.code(t)+`"}`, c)
	if w.Code != http.StatusNoContent {
		t.Fatalf("code step: %d %s", w.Code, w.Body)
	}
	return sessionCookie(t, w)
}

// readyGate is a gate with the test account signed in.
func readyGate(t *testing.T) (*gate, *http.Cookie, *testEnv) {
	t.Helper()
	e := newTestEnv(t).withAccount(t)
	return e.g, e.signIn(t), e
}

func testWorkbenchAssets(t *testing.T) string {
	t.Helper()
	assets := t.TempDir()
	for _, name := range workbenchFiles {
		// The engine and its runtime are built at release; the tests serve stand-ins.
		body := []byte("stand-in " + name)
		if name != "rootwell.wasm" && name != "wasm_exec.js" {
			var err error
			if body, err = os.ReadFile(filepath.Join("..", "..", "web", "workbench", name)); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(assets, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return assets
}

func call(g *gate, method, route, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://"+localHost+route, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPost || method == http.MethodDelete {
		r.Header.Set("Origin", "https://"+localHost)
		r.Header.Set("X-Rootwell-Request", "1")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

// apiCall sends a request with an explicit Origin and, when header is set, the
// page's X-Rootwell-Request header.
func apiCall(g *gate, method, route, body string, cookie *http.Cookie, origin string, header bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://"+localHost+route, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if header {
		r.Header.Set("X-Rootwell-Request", "1")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func sessionCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName && c.MaxAge > 0 {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func status(t *testing.T, g *gate, c *http.Cookie) map[string]any {
	t.Helper()
	w := call(g, "GET", "/api/session", "", c)
	var out map[string]any
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("session status: %d %s", w.Code, w.Body)
	}
	// No session is an answer, never an error the browser would log.
	if out["stage"] == "none" {
		if len(out) != 1 {
			t.Fatalf("no session says more: %v", out)
		}
		return nil
	}
	return out
}

func page(g *gate, path string, c *http.Cookie) int {
	return call(g, "GET", path, "", c).Code
}

func TestSetupSavesTheAccountOnlyOnceThePhoneIsConfirmed(t *testing.T) {
	e := newTestEnv(t)
	code, _, err := e.g.accounts.NewSetupCode("")
	if err != nil {
		t.Fatal(err)
	}
	for _, public := range []string{"/login", "/setup"} {
		if got := page(e.g, public, nil); got != http.StatusOK {
			t.Fatalf("%s: %d", public, got)
		}
	}
	if w := call(e.g, "POST", "/api/setup", `{"code":"aaaaaa-bbbbbb-cccccc-dddddd","name":"ada","password":"`+testPassword+`"}`, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong setup code: %d", w.Code)
	}
	if w := call(e.g, "POST", "/api/setup", `{"code":"`+code+`","name":"ada","password":"too short"}`, nil); w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "too short") {
		t.Fatalf("a short password: %d %s", w.Code, w.Body)
	}
	if w := call(e.g, "POST", "/api/setup", `{"code":"`+code+`","name":"ada lovelace","password":"`+testPassword+`"}`, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("a name with a space: %d", w.Code)
	}
	w := call(e.g, "POST", "/api/setup", `{"code":"`+code+`","name":"Ada","password":"`+testPassword+`"}`, nil)
	var started struct {
		Name string   `json:"name"`
		Key  string   `json:"key"`
		QR   []string `json:"qr"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &started) != nil || started.Name != "ada" || len(started.Key) != 32 || len(started.QR) < 21 {
		t.Fatalf("setup start: %d %s", w.Code, w.Body)
	}
	for _, row := range started.QR {
		if len(row) != len(started.QR) || strings.Trim(row, "01") != "" {
			t.Fatalf("a QR row that is not modules: %q", row)
		}
	}
	setup := sessionCookie(t, w)
	if exists, _ := e.g.accounts.Exists(); exists {
		t.Fatal("the account was saved before its phone was confirmed")
	}
	if got := page(e.g, "/certificates", setup); got != http.StatusSeeOther {
		t.Fatalf("a setup session reached a page: %d", got)
	}
	if w := call(e.g, "POST", "/api/setup/confirm", `{"code":"000000"}`, setup); w.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong phone code: %d", w.Code)
	}
	w = call(e.g, "POST", "/api/setup/confirm", `{"code":"`+phoneCode(t, started.Key, e.clock.now())+`"}`, setup)
	var finished struct {
		Codes []string `json:"recovery_codes"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &finished) != nil || len(finished.Codes) != 10 {
		t.Fatalf("setup confirm: %d %s", w.Code, w.Body)
	}
	ready := sessionCookie(t, w)
	if ready.Value == setup.Value {
		t.Fatal("the session kept its token from setup")
	}
	if got := page(e.g, "/certificates", ready); got != http.StatusOK {
		t.Fatalf("signed in after setup: %d", got)
	}
	if got := status(t, e.g, setup); got != nil {
		t.Fatalf("the setup token still works: %v", got)
	}
	if w := call(e.g, "POST", "/api/setup", `{"code":"`+code+`","name":"bob","password":"`+testPassword+`"}`, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("a spent setup code: %d", w.Code)
	}
}

func TestSignInTakesThePasswordThenACode(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	wrong := call(e.g, "POST", "/api/session", `{"name":"ada","password":"not the password at all"}`, nil)
	unknown := call(e.g, "POST", "/api/session", `{"name":"bob","password":"`+testPassword+`"}`, nil)
	if wrong.Code != http.StatusUnauthorized || unknown.Code != http.StatusUnauthorized || wrong.Body.String() != unknown.Body.String() {
		t.Fatalf("a wrong password and an unknown name differ: %d %q, %d %q", wrong.Code, wrong.Body, unknown.Code, unknown.Body)
	}
	c := e.passwordStep(t, testPassword)
	if got := status(t, e.g, c); got["stage"] != "code" || got["name"] != nil {
		t.Fatalf("after the password: %v", got)
	}
	if got := page(e.g, "/certificates", c); got != http.StatusSeeOther {
		t.Fatalf("the code stage reached a page: %d", got)
	}
	if w := call(e.g, "GET", "/api/inventory", "", c); w.Code != http.StatusUnauthorized {
		t.Fatalf("the code stage reached the list: %d", w.Code)
	}
	if w := call(e.g, "POST", "/api/session/code", `{"code":"000000"}`, c); w.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong code: %d", w.Code)
	}
	w := call(e.g, "POST", "/api/session/code", `{"code":"`+e.code(t)+`"}`, c)
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("the code: %d %s", w.Code, w.Body)
	}
	ready := sessionCookie(t, w)
	if ready.Value == c.Value || status(t, e.g, c) != nil {
		t.Fatal("the session kept its token from the password step")
	}
	got := status(t, e.g, ready)
	if got["stage"] != "ready" || got["name"] != testName || got["recovery_left"] != float64(10) || got["fresh"] != true {
		t.Fatalf("signed in: %v", got)
	}
	// A recovery code signs in instead of the phone, once.
	c = e.passwordStep(t, testPassword)
	w = call(e.g, "POST", "/api/session/code", `{"code":"`+strings.ToUpper(e.recovery[0])+`"}`, c)
	if got := recoveryLeft(t, w); got != 9 {
		t.Fatalf("a recovery code left %d", got)
	}
	if got := status(t, e.g, sessionCookie(t, w)); got["stage"] != "ready" || got["recovery_left"] != float64(9) {
		t.Fatalf("signed in with a recovery code: %v", got)
	}
	c = e.passwordStep(t, testPassword)
	if w := call(e.g, "POST", "/api/session/code", `{"code":"`+e.recovery[0]+`"}`, c); w.Code != http.StatusUnauthorized {
		t.Fatalf("a recovery code twice: %d", w.Code)
	}
	// The code step waits five minutes for the code.
	c = e.passwordStep(t, testPassword)
	e.clock.add(codeLife)
	if w := call(e.g, "POST", "/api/session/code", `{"code":"`+e.code(t)+`"}`, c); w.Code != http.StatusUnauthorized {
		t.Fatalf("a code after five minutes: %d", w.Code)
	}
}

func TestSessionsEndWhenIdleOrOldAndAStatusCheckIsNotUse(t *testing.T) {
	g, c, e := readyGate(t)
	e.clock.add(14 * time.Minute)
	if got := page(g, "/certificates", c); got != http.StatusOK {
		t.Fatalf("after 14 minutes: %d", got)
	}
	e.clock.add(14 * time.Minute)
	if status(t, g, c) == nil {
		t.Fatal("the session ended early")
	}
	e.clock.add(2 * time.Minute)
	if got := page(g, "/certificates", c); got != http.StatusSeeOther {
		t.Fatalf("16 minutes idle: %d", got)
	}
	c = e.signIn(t)
	for range 47 {
		e.clock.add(10 * time.Minute)
		if got := page(g, "/certificates", c); got != http.StatusOK {
			t.Fatalf("in use within eight hours: %d", got)
		}
	}
	e.clock.add(10 * time.Minute)
	if got := page(g, "/certificates", c); got != http.StatusSeeOther {
		t.Fatalf("after eight hours: %d", got)
	}
	// A restart ends every session; the account stays.
	c = e.signIn(t)
	e.reopen(t)
	if status(t, e.g, c) != nil {
		t.Fatal("a session survived a restart")
	}
	e.signIn(t)
}

func signInFrom(g *gate, source, name, password string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://"+localHost+"/api/session", strings.NewReader(`{"name":"`+name+`","password":"`+password+`"}`))
	r.RemoteAddr = source
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://"+localHost)
	r.Header.Set("X-Rootwell-Request", "1")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func TestOnlyFailuresCountPerNameAndPerSource(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	// Successes cost nothing.
	for range 8 {
		e.passwordStep(t, testPassword)
	}
	for i := range nameFailures {
		if w := signInFrom(e.g, "192.0.2.1:1", testName, "not the password at all"); w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, w.Code)
		}
	}
	w := signInFrom(e.g, "192.0.2.1:1", testName, testPassword)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("after five failures: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	// The name waits from every address; other names do not.
	if w := signInFrom(e.g, "198.51.100.7:1", testName, testPassword); w.Code != http.StatusTooManyRequests {
		t.Fatalf("the name from another address: %d", w.Code)
	}
	if w := signInFrom(e.g, "192.0.2.1:1", "bob", "not the password at all"); w.Code != http.StatusUnauthorized {
		t.Fatalf("another name: %d", w.Code)
	}
	e.clock.add(time.Minute)
	if w := signInFrom(e.g, "192.0.2.1:1", testName, "not the password at all"); w.Code != http.StatusUnauthorized {
		t.Fatalf("after the wait: %d", w.Code)
	}
	if w := signInFrom(e.g, "192.0.2.1:1", testName, testPassword); w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "120" {
		t.Fatalf("the next failure doubles the wait: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	// Twenty failures from one address, over any names, make it wait.
	for i := range sourceFailures {
		signInFrom(e.g, "[2001:db8::1]:1", fmt.Sprintf("name%d", i), "not the password at all")
	}
	if w := signInFrom(e.g, "[2001:db8::2]:1", "carol", "not the password at all"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("the same /64: %d", w.Code)
	}
	if w := signInFrom(e.g, "[2001:db8:0:1::1]:1", "carol", "not the password at all"); w.Code != http.StatusUnauthorized {
		t.Fatalf("another /64: %d", w.Code)
	}
}

func TestAFullFailureTableHoldsNewNamesRatherThanForgetALock(t *testing.T) {
	e := newTestEnv(t)
	now := e.clock.now()
	for i := range maxLimitKeys {
		e.g.failures[fmt.Sprintf("name:n%d", i)] = &failures{count: nameFailures, last: now, until: now.Add(time.Hour)}
	}
	if wait := e.g.try(nameLimit("fresh")); wait != 0 {
		t.Fatalf("the first failure waits %v", wait)
	}
	if len(e.g.failures) != maxLimitKeys || waitFor(e.g, nameLimit("fresh")) != time.Minute || waitFor(e.g, nameLimit("n1")) <= time.Minute {
		t.Fatalf("full table: %d entries, wait %v", len(e.g.failures), waitFor(e.g, nameLimit("fresh")))
	}
}

func TestAFreshCodeGuardsChangesToHowTheAccountSignsIn(t *testing.T) {
	g, c, e := readyGate(t)
	w := call(g, "POST", "/api/recovery-codes", `{}`, c)
	if w.Code != http.StatusOK {
		t.Fatalf("right after sign-in: %d", w.Code)
	}
	c = sessionCookie(t, w)
	e.clock.add(freshLife)
	for _, route := range []string{"/api/recovery-codes", "/api/phone"} {
		if w := call(g, "POST", route, `{}`, c); w.Code != http.StatusPreconditionRequired {
			t.Fatalf("%s ten minutes later: %d", route, w.Code)
		}
	}
	if w := call(g, "POST", "/api/password", `{"password":"`+testPassword+`","next":"`+nextTestPassword+`"}`, c); w.Code != http.StatusPreconditionRequired {
		t.Fatalf("a password change ten minutes later: %d", w.Code)
	}
	if w := call(g, "POST", "/api/fresh", `{"code":"000000"}`, c); w.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong fresh code: %d", w.Code)
	}
	w = call(g, "POST", "/api/fresh", `{"code":"`+e.code(t)+`"}`, c)
	if w.Code != http.StatusNoContent {
		t.Fatalf("a fresh code: %d", w.Code)
	}
	c = sessionCookie(t, w)
	if w := call(g, "POST", "/api/phone", `{}`, c); w.Code != http.StatusOK {
		t.Fatalf("after a fresh code: %d", w.Code)
	}
	// Five wrong codes end the session.
	for i := range wrongCodesEnd {
		w := call(g, "POST", "/api/fresh", `{"code":"000000"}`, c)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: %d", i, w.Code)
		}
	}
	if status(t, g, c) != nil {
		t.Fatal("the session outlived five wrong codes")
	}
}

func TestAPasswordChangeEndsEverySession(t *testing.T) {
	g, first, e := readyGate(t)
	second := e.signIn(t)
	if w := call(g, "POST", "/api/password", `{"password":"not the password at all","next":"`+nextTestPassword+`"}`, first); w.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong current password: %d", w.Code)
	}
	for _, next := range []string{testPassword, "too short", strings.Repeat("x", 1025)} {
		w := call(g, "POST", "/api/password", `{"password":"`+testPassword+`","next":"`+next+`"}`, first)
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), next) {
			t.Fatalf("new password %.20q: %d %s", next, w.Code, w.Body)
		}
	}
	w := call(g, "POST", "/api/password", `{"password":"`+testPassword+`","next":"`+nextTestPassword+`"}`, first)
	if w.Code != http.StatusNoContent {
		t.Fatalf("password change: %d %s", w.Code, w.Body)
	}
	if status(t, g, first) != nil || status(t, g, second) != nil {
		t.Fatal("a session outlived the password change")
	}
	if w := call(g, "POST", "/api/session", `{"name":"ada","password":"`+testPassword+`"}`, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("the old password: %d", w.Code)
	}
	e.passwordStep(t, nextTestPassword)
}

func TestANewPhoneKeepsThisSessionAndEndsTheOthers(t *testing.T) {
	g, first, e := readyGate(t)
	second := e.signIn(t)
	w := call(g, "POST", "/api/phone", `{}`, first)
	var started struct {
		Key string `json:"key"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &started) != nil || started.Key == e.seed {
		t.Fatalf("new phone: %d %s", w.Code, w.Body)
	}
	if w := call(g, "POST", "/api/phone/confirm", `{"code":"`+e.code(t)+`"}`, first); w.Code != http.StatusUnauthorized {
		t.Fatalf("the old phone confirmed the new key: %d", w.Code)
	}
	old := e.seed
	e.seed = started.Key
	w = call(g, "POST", "/api/phone/confirm", `{"code":"`+e.code(t)+`"}`, first)
	if w.Code != http.StatusNoContent {
		t.Fatalf("confirm: %d %s", w.Code, w.Body)
	}
	kept := sessionCookie(t, w)
	if status(t, g, kept) == nil || status(t, g, second) != nil || status(t, g, first) != nil {
		t.Fatal("the phone change kept the wrong sessions")
	}
	c := e.passwordStep(t, testPassword)
	e.clock.add(30 * time.Second)
	if w := call(g, "POST", "/api/session/code", `{"code":"`+phoneCode(t, old, e.clock.now())+`"}`, c); w.Code != http.StatusUnauthorized {
		t.Fatalf("the old phone signed in: %d", w.Code)
	}
	if w := call(g, "POST", "/api/session/code", `{"code":"`+phoneCode(t, e.seed, e.clock.now())+`"}`, c); w.Code != http.StatusNoContent {
		t.Fatalf("the new phone: %d", w.Code)
	}
}

func TestNewRecoveryCodesReplaceTheOldOnes(t *testing.T) {
	g, c, e := readyGate(t)
	w := call(g, "POST", "/api/recovery-codes", `{}`, c)
	var out struct {
		Codes []string `json:"recovery_codes"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Codes) != 10 {
		t.Fatalf("new codes: %d %s", w.Code, w.Body)
	}
	c = e.passwordStep(t, testPassword)
	if w := call(g, "POST", "/api/session/code", `{"code":"`+e.recovery[1]+`"}`, c); w.Code != http.StatusUnauthorized {
		t.Fatalf("an old recovery code: %d", w.Code)
	}
	if got := recoveryLeft(t, call(g, "POST", "/api/session/code", `{"code":"`+out.Codes[1]+`"}`, c)); got != 9 {
		t.Fatalf("a new recovery code left %d", got)
	}
}

// recoveryLeft reads the answer to a right recovery code: exactly how many
// are left, and nothing else.
func recoveryLeft(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	var out map[string]int
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out) != 1 {
		t.Fatalf("after a recovery code: %d %q", w.Code, w.Body)
	}
	left, ok := out["recovery_left"]
	if !ok {
		t.Fatalf("after a recovery code: %q", w.Body)
	}
	return left
}

// A phone code is answered with nothing. A recovery code, at sign-in or for a
// fresh code, is answered with how many are left, down to none, so the page
// can say so before they run out.
func TestARecoveryCodeSaysHowManyAreLeft(t *testing.T) {
	g, c, e := readyGate(t)
	w := call(g, "POST", "/api/fresh", `{"code":"`+e.code(t)+`"}`, c)
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("a fresh phone code: %d %q", w.Code, w.Body)
	}
	c = sessionCookie(t, w)
	w = call(g, "POST", "/api/fresh", `{"code":"`+e.recovery[0]+`"}`, c)
	if got := recoveryLeft(t, w); got != 9 {
		t.Fatalf("a fresh recovery code left %d", got)
	}
	c = sessionCookie(t, w)
	if got := status(t, g, c); got["stage"] != "ready" || got["fresh"] != true || got["recovery_left"] != float64(9) {
		t.Fatalf("after a fresh recovery code: %v", got)
	}
	for i := 1; i < 10; i++ {
		w := call(g, "POST", "/api/session/code", `{"code":"`+e.recovery[i]+`"}`, e.passwordStep(t, testPassword))
		if got := recoveryLeft(t, w); got != 9-i {
			t.Fatalf("recovery code %d left %d", i, got)
		}
	}
	if w := call(g, "POST", "/api/fresh", `{"code":"`+e.recovery[9]+`"}`, c); w.Code != http.StatusUnauthorized {
		t.Fatalf("a spent recovery code for a fresh code: %d %q", w.Code, w.Body)
	}
}

func TestTheSessionCookieIsHostOnlySecureAndStrict(t *testing.T) {
	g, c, e := readyGate(t)
	if c.Name != "__Host-rootwell_session" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.MaxAge != int(absoluteLife/time.Second) {
		t.Fatalf("cookie: %+v", c)
	}
	// Two session cookies count as none, in either order, so a planted one
	// cannot pick a session.
	planted := &http.Cookie{Name: cookieName, Value: strings.Repeat("A", 43)}
	for _, pair := range [][2]*http.Cookie{{c, planted}, {planted, c}} {
		r := httptest.NewRequest("GET", "https://"+localHost+"/certificates", nil)
		r.AddCookie(pair[0])
		r.AddCookie(pair[1])
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("two cookies: %d", w.Code)
		}
	}
	// Sign-out ends only this session.
	other := e.signIn(t)
	if w := call(g, "DELETE", "/api/session", "", c); w.Code != http.StatusNoContent {
		t.Fatalf("sign out: %d", w.Code)
	}
	if status(t, g, c) != nil || status(t, g, other) == nil {
		t.Fatal("sign-out ended the wrong session")
	}
}

func TestTheSessionTableIsBoundedWithoutEndingOtherAccounts(t *testing.T) {
	e := newTestEnv(t)
	for i := range maxSessions {
		if err := e.g.issue(httptest.NewRecorder(), [32]byte{}, session{stage: stageReady, name: fmt.Sprintf("n%d", i%2)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.g.issue(httptest.NewRecorder(), [32]byte{}, session{stage: stageReady, name: "third"}); err != errTooManySessions {
		t.Fatalf("a full table took a third account: %v", err)
	}
	if err := e.g.issue(httptest.NewRecorder(), [32]byte{}, session{stage: stageReady, name: "n0"}); err != nil || len(e.g.sessions) != maxSessions {
		t.Fatalf("an account's newest session: %v, %d sessions", err, len(e.g.sessions))
	}
}

func TestPagesAndScriptsNeedASignInAndWorkersReachNoNetwork(t *testing.T) {
	g, ready, e := readyGate(t)
	codeStage := e.passwordStep(t, testPassword)
	shared := map[string]bool{"/rootwell.css": true, "/theme.js": true, "/favicon.svg": true}
	private := []string{"/", "/account", "/installation", "/website-check", "/website-check.js", "/certificate-pfx.js", "/certificate-pfx-worker.js"}
	for path := range workbenchFiles {
		if !shared[path] {
			private = append(private, path)
		}
	}
	for _, path := range private {
		for _, c := range []*http.Cookie{nil, codeStage} {
			if w := call(g, "GET", path, "", c); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
				t.Fatalf("%s before sign-in: %d %q", path, w.Code, w.Header().Get("Location"))
			}
		}
		if w := call(g, "GET", path, "", ready); w.Code != http.StatusOK && !(path == "/" && w.Code == http.StatusSeeOther) {
			t.Fatalf("%s signed in: %d", path, w.Code)
		}
	}
	for _, public := range []string{"/login", "/setup", "/auth.js", "/qr.js", "/passkey.js", "/rootwell.css", "/theme.js", "/favicon.svg", "/schibsted-grotesk.woff2"} {
		if got := page(g, public, nil); got != http.StatusOK {
			t.Fatalf("%s is not public: %d", public, got)
		}
	}
	// The workers open keys and passwords: they may reach nothing.
	for _, worker := range []string{"/private-key-worker.js", "/pfx-worker.js", "/csr-worker.js", "/certificate-pfx-worker.js"} {
		csp := call(g, "GET", worker, "", ready).Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "connect-src 'none'") || !strings.Contains(csp, "worker-src 'none'") || strings.Contains(csp, "connect-src 'self'") {
			t.Fatalf("%s policy: %q", worker, csp)
		}
	}
}

func TestGateRejectsCrossOriginHostAndMalformedRequests(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	g := e.g
	malformed := []string{`{`, `{"name":"ada","password":"x","unknown":1}`, `{"name":"ada","password":"x"}{}`, strings.Repeat("x", 4097)}
	for _, body := range malformed {
		if w := call(g, "POST", "/api/session", body, nil); w.Code != http.StatusBadRequest {
			t.Fatalf("a malformed request: %d", w.Code)
		}
	}
	r := httptest.NewRequest("POST", "https://"+localHost+"/api/session", strings.NewReader(`{"name":"ada","password":"`+testPassword+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://attacker.invalid")
	r.Header.Set("X-Rootwell-Request", "1")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin sign-in: %d", w.Code)
	}
	r.Header.Set("Origin", "https://"+localHost)
	r.Host = "attacker.invalid"
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("DNS-rebound Host: %d", w.Code)
	}
	r.Host = localHost
	r.Header.Del("X-Rootwell-Request")
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a request without the page header: %d", w.Code)
	}
	r.Header.Set("X-Rootwell-Request", "1")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site Fetch Metadata: %d", w.Code)
	}
	if w := call(g, "GET", "/%2e%2e/rootwell.db", "", nil); w.Code == http.StatusOK {
		t.Fatal("path traversal returned a file")
	}
	if w := call(g, "GET", "/login?password=secret", "", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("a password-bearing query: %d", w.Code)
	}
	form := httptest.NewRequest("POST", "https://"+localHost+"/api/session", strings.NewReader("name=ada&password="+testPassword))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form.Header.Set("Origin", "https://"+localHost)
	form.Header.Set("X-Rootwell-Request", "1")
	w = httptest.NewRecorder()
	g.ServeHTTP(w, form)
	if w.Code < 400 || strings.Contains(w.Body.String(), testPassword) {
		t.Fatalf("a form post was accepted or echoed: %d", w.Code)
	}
}

func TestAuthFormsCannotFallBackToPasswordInGetURL(t *testing.T) {
	for _, item := range []struct{ name, action string }{
		{"auth/login.html", "/api/session"},
		{"auth/setup.html", "/api/setup"},
		{"auth/account.html", "/api/password"},
	} {
		body, err := authAssets.ReadFile(item.name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte(`method="post" action="`+item.action+`"`)) {
			t.Fatalf("%s could submit a password by default GET", item.name)
		}
	}
}

func TestGatewayRefusesIncompleteBrowserAssets(t *testing.T) {
	assets := t.TempDir()
	if err := os.WriteFile(filepath.Join(assets, "certificates.html"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if g, err := newGate(nil, assets, servingstore.Serving{}); err == nil {
		_ = g.Close()
		t.Fatal("gateway started with missing browser engine")
	}
}

// waitFor is how long keys must still wait, without counting an attempt.
func waitFor(g *gate, keys ...limitKey) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.waitLocked(g.now(), keys)
}
