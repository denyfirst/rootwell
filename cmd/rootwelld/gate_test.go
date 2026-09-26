package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

const initialTestPassword = "an initial password for testing"
const nextTestPassword = "a different long test password"

func testGate(t *testing.T) (*gate, string) {
	t.Helper()
	data := t.TempDir()
	path := filepath.Join(data, "access.json")
	if err := instanceaccess.Create(path, initialTestPassword); err != nil {
		t.Fatal(err)
	}
	assets := t.TempDir()
	for name, body := range map[string]string{
		"index.html": "protected workbench", "app.js": "protected javascript", "rootwell.wasm": "protected wasm",
		"style.css": "protected css", "theme.js": "protected theme", "wasm-loader.js": "protected loader", "wasm_exec.js": "protected runtime",
	} {
		if err := os.WriteFile(filepath.Join(assets, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g, err := newGate(path, assets, localHost)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g, path
}

func call(g *gate, method, route, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+localHost+route, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPost || method == http.MethodDelete {
		r.Header.Set("Origin", "http://"+localHost)
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
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestInitialLoginIsSetupOnlyUntilPasswordChange(t *testing.T) {
	g, path := testGate(t)
	if w := call(g, "GET", "/", "", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("unguarded Workbench: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := call(g, "GET", "/app.js", "", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("unguarded asset: %d", w.Code)
	}
	loginPage := call(g, "GET", "/login", "", nil)
	if loginPage.Code != http.StatusOK || loginPage.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(loginPage.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("login page is unavailable or missing security headers")
	}
	login := call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil)
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), `"mode":"setup"`) {
		t.Fatalf("setup sign-in: %d %s", login.Code, login.Body.String())
	}
	cookie := sessionCookie(t, login)
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatal("session cookie lacks required protections")
	}
	if cookie.MaxAge != 15*60 {
		t.Fatal("setup session lives longer than fifteen minutes")
	}
	secondLogin := call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil)
	if secondLogin.Code != http.StatusOK {
		t.Fatalf("second setup session: %d", secondLogin.Code)
	}
	secondCookie := sessionCookie(t, secondLogin)
	for _, route := range []string{"/", "/index.html", "/app.js", "/rootwell.wasm", "/account"} {
		w := call(g, "GET", route, "", cookie)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup" {
			t.Fatalf("setup credential reached %s: %d", route, w.Code)
		}
	}
	if w := call(g, "GET", "/setup", "", cookie); w.Code != http.StatusOK {
		t.Fatalf("setup page unavailable: %d", w.Code)
	}
	bad := call(g, "POST", "/api/password", `{"password":"wrong current password","next":"`+nextTestPassword+`"}`, cookie)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current password: %d", bad.Code)
	}
	if _, err := instanceaccess.Open(path, initialTestPassword); !errors.Is(err, instanceaccess.ErrChangeRequired) {
		t.Fatalf("failed change activated key: %v", err)
	}
	changed := call(g, "POST", "/api/password", `{"password":"`+initialTestPassword+`","next":"`+nextTestPassword+`"}`, cookie)
	if changed.Code != http.StatusNoContent {
		t.Fatalf("password change: %d %s", changed.Code, changed.Body.String())
	}
	if w := call(g, "GET", "/", "", cookie); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("setup session survived change: %d", w.Code)
	}
	if w := call(g, "GET", "/setup", "", secondCookie); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("second setup session survived change: %d", w.Code)
	}
	key, err := instanceaccess.Open(path, nextTestPassword)
	if err != nil || len(key) != 32 {
		t.Fatalf("new password did not open key: %v", err)
	}
	if _, err := instanceaccess.Open(path, initialTestPassword); !errors.Is(err, instanceaccess.ErrWrongPassword) {
		t.Fatalf("initial password still works: %v", err)
	}
	ready := call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil)
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `"mode":"ready"`) {
		t.Fatalf("ready sign-in: %d %s", ready.Code, ready.Body.String())
	}
	readyCookie := sessionCookie(t, ready)
	if w := call(g, "GET", "/", "", readyCookie); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "protected workbench") {
		t.Fatalf("Workbench unavailable after change: %d", w.Code)
	}
	if w := call(g, "GET", "/app.js", "", readyCookie); w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("protected asset: %d", w.Code)
	}
	if w := call(g, "GET", "/account", "", readyCookie); w.Code != http.StatusOK {
		t.Fatalf("account page: %d", w.Code)
	}
	if w := call(g, "GET", "/access.json", "", readyCookie); w.Code != http.StatusNotFound {
		t.Fatalf("access file route exposed: %d", w.Code)
	}
}

func TestGateRejectsCrossOriginHostAndMalformedAuthentication(t *testing.T) {
	g, _ := testGate(t)
	malformed := []string{`{`, `{"password":"x","unknown":1}`, `{"password":"x"}{}`, strings.Repeat("x", 2049)}
	for _, body := range malformed {
		w := call(g, "POST", "/api/session", body, nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("malformed request was accepted: %d", w.Code)
		}
	}
	r := httptest.NewRequest("POST", "http://"+localHost+"/api/session", strings.NewReader(`{"password":"`+initialTestPassword+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://attacker.invalid")
	r.Header.Set("X-Rootwell-Request", "1")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login: %d", w.Code)
	}
	r.Header.Set("Origin", "http://"+localHost)
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
		t.Fatalf("request without anti-CSRF header: %d", w.Code)
	}
	r.Header.Set("X-Rootwell-Request", "1")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site Fetch Metadata accepted: %d", w.Code)
	}
	if w := call(g, "GET", "/%2e%2e/access.json", "", nil); w.Code == http.StatusOK {
		t.Fatal("path traversal returned a file")
	}
	if w := call(g, "GET", "/login?password=secret", "", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("password-bearing query accepted: %d", w.Code)
	}
}

func TestGateRateLimitsAndExpiresSessions(t *testing.T) {
	g, _ := testGate(t)
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		w := call(g, "POST", "/api/session", `{"password":"incorrect password"}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if w := call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("limit bypass: %d", w.Code)
	}
	now = now.Add(time.Minute)
	login := call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("after rate-limit interval: %d", login.Code)
	}
	cookie := sessionCookie(t, login)
	now = now.Add(15 * time.Minute)
	if w := call(g, "GET", "/setup", "", cookie); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("expired session still active: %d", w.Code)
	}
}

func TestReadyPasswordChangeRevokesAllSessionsAndLogoutOnlyOwn(t *testing.T) {
	g, path := testGate(t)
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	first := call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil)
	second := call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil)
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("ready sign-in failed: %d %d", first.Code, second.Code)
	}
	firstCookie, secondCookie := sessionCookie(t, first), sessionCookie(t, second)
	if w := call(g, "DELETE", "/api/session", "", firstCookie); w.Code != http.StatusNoContent {
		t.Fatalf("sign-out failed: %d", w.Code)
	}
	if w := call(g, "GET", "/", "", firstCookie); w.Code != http.StatusSeeOther {
		t.Fatal("signed-out session still opens Workbench")
	}
	if w := call(g, "GET", "/", "", secondCookie); w.Code != http.StatusOK {
		t.Fatal("signing out one session revoked another")
	}
	third := call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil)
	if third.Code != http.StatusOK {
		t.Fatalf("third sign-in failed: %d", third.Code)
	}
	thirdCookie := sessionCookie(t, third)
	replacement := "a third distinct and long password"
	changed := call(g, "POST", "/api/password", `{"password":"`+nextTestPassword+`","next":"`+replacement+`"}`, secondCookie)
	if changed.Code != http.StatusNoContent {
		t.Fatalf("ready password change failed: %d", changed.Code)
	}
	for _, oldCookie := range []*http.Cookie{secondCookie, thirdCookie} {
		if w := call(g, "GET", "/", "", oldCookie); w.Code != http.StatusSeeOther {
			t.Fatal("password change left a ready session active")
		}
	}
	if _, err := instanceaccess.Open(path, nextTestPassword); !errors.Is(err, instanceaccess.ErrWrongPassword) {
		t.Fatalf("old ready password still works: %v", err)
	}
	if key, err := instanceaccess.Open(path, replacement); err != nil || len(key) != 32 {
		t.Fatalf("new ready password does not open key: %v", err)
	}
}

func TestInitRequiresSaveConfirmationAndNeverReprintsPassword(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	var output bytes.Buffer
	if err := initialize(dir, strings.NewReader("NO\n"), &output); err == nil {
		t.Fatal("unconfirmed init created installation")
	}
	if _, err := os.Stat(filepath.Join(dir, "access.json")); !os.IsNotExist(err) {
		t.Fatal("unconfirmed init left access file")
	}
	output.Reset()
	if err := initialize(dir, strings.NewReader("SAVED\n"), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "setup password") {
		t.Fatal("interactive init did not show password")
	}
	output.Reset()
	if err := initialize(dir, strings.NewReader("SAVED\n"), &output); err == nil || output.Len() != 0 {
		t.Fatal("existing password was reprinted or replaced")
	}
	body, err := os.ReadFile(filepath.Join(dir, "access.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil || envelope["state"] != "change-required" {
		t.Fatalf("unexpected init state: %v", err)
	}
}

func TestAuthFormsCannotFallBackToPasswordInGetURL(t *testing.T) {
	for _, item := range []struct{ name, action string }{
		{"auth/login.html", "/api/session"},
		{"auth/setup.html", "/api/password"},
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
	g, _ := testGate(t)
	r := httptest.NewRequest("POST", "http://"+localHost+"/api/session", strings.NewReader("password="+initialTestPassword))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://"+localHost)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), initialTestPassword) {
		t.Fatal("non-JavaScript form submission was accepted or echoed a password")
	}
}

func TestGatewayRefusesIncompleteBrowserAssets(t *testing.T) {
	assets := t.TempDir()
	if err := os.WriteFile(filepath.Join(assets, "index.html"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if g, err := newGate(filepath.Join(t.TempDir(), "access.json"), assets, localHost); err == nil {
		_ = g.Close()
		t.Fatal("gateway started with missing browser engine")
	}
}

func TestPasswordChangeValidationIsSpecificWithoutEchoingSecrets(t *testing.T) {
	g, _ := testGate(t)
	login := call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("setup sign-in: %d", login.Code)
	}
	cookie := sessionCookie(t, login)
	for _, next := range []string{initialTestPassword, strings.Repeat("x", 1025)} {
		w := call(g, "POST", "/api/password", `{"password":"`+initialTestPassword+`","next":"`+next+`"}`, cookie)
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), next) {
			t.Fatalf("replacement validation was unsafe or unclear: %d", w.Code)
		}
	}
}
