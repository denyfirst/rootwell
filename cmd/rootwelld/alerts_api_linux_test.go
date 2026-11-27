//go:build linux

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const alertToken = "123456789:AAH-synthetic_token_for_tests_only_000"

func alertSettings(t *testing.T, e *testEnv, cookie *http.Cookie) (string, alertsOutput) {
	t.Helper()
	w := apiCall(e.g, "GET", "/api/alerts", "", cookie, "", true)
	var out alertsOutput
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("alerts: %d %s", w.Code, w.Body)
	}
	return w.Body.String(), out
}

func TestLinuxAlertSettingsNeedAFreshCodeAndNeverShowSecrets(t *testing.T) {
	_, cookie, e := readyGate(t)
	if body, out := alertSettings(t, e, cookie); out.Email != nil || out.Telegram != nil || !strings.Contains(body, `"log":[]`) {
		t.Fatalf("a new vault's alerts: %s", body)
	}
	if w := post(t, e, cookie, "/api/alerts/telegram", map[string]any{"token": alertToken, "chat_id": "-1001234567890"}); w.code != http.StatusNoContent {
		t.Fatalf("save Telegram: %d %s", w.code, w.body)
	}
	email := map[string]any{"host": "mail.rootwell.test", "port": 587, "security": "starttls", "username": "alerts", "password": "a mail password",
		"from": "rootwell@rootwell.test", "to": []string{"ops@rootwell.test"}}
	if w := post(t, e, cookie, "/api/alerts/email", email); w.code != http.StatusNoContent {
		t.Fatalf("save e-mail: %d %s", w.code, w.body)
	}
	body, out := alertSettings(t, e, cookie)
	if out.Telegram == nil || out.Telegram.ChatID != "-1001234567890" || out.Email == nil || !out.Email.HasPassword ||
		strings.Contains(body, "AAH-") || strings.Contains(body, "a mail password") {
		t.Fatalf("the settings show %s", body)
	}
	// Ten minutes later: changing or turning off needs a phone code again.
	e.clock.add(freshLife)
	for route, input := range map[string]map[string]any{
		"/api/alerts/telegram": {"token": "", "keep_token": true, "chat_id": "42"},
		"/api/alerts/email":    {"host": "mail.evil.invalid", "port": 587, "security": "starttls", "username": "alerts", "password": "", "keep_password": true, "from": "rootwell@rootwell.test", "to": []string{"x@evil.invalid"}},
		"/api/alerts/remove":   {"channel": "telegram"},
	} {
		if w := post(t, e, cookie, route, input); w.code != http.StatusPreconditionRequired {
			t.Fatalf("%s without a fresh code: %d %s", route, w.code, w.body)
		}
	}
	if _, after := alertSettings(t, e, cookie); after.Telegram == nil || after.Telegram.ChatID != "-1001234567890" || after.Email.Host != "mail.rootwell.test" {
		t.Fatalf("a refused change wrote: %+v", after)
	}
	fresh := apiCall(e.g, "POST", "/api/fresh", `{"code":"`+e.code(t)+`"}`, cookie, "https://"+localHost, true)
	if fresh.Code != http.StatusNoContent {
		t.Fatalf("fresh code: %d", fresh.Code)
	}
	cookie = sessionCookie(t, fresh)
	if w := post(t, e, cookie, "/api/alerts/remove", map[string]any{"channel": "telegram"}); w.code != http.StatusNoContent {
		t.Fatalf("turn off: %d %s", w.code, w.body)
	}
	if _, after := alertSettings(t, e, cookie); after.Telegram != nil {
		t.Fatal("Telegram is still on")
	}
	// The token is gone with it: keeping it now is refused.
	if w := post(t, e, cookie, "/api/alerts/telegram", map[string]any{"token": "", "keep_token": true, "chat_id": "42"}); w.code != http.StatusBadRequest {
		t.Fatalf("a forgotten token was kept: %d %s", w.code, w.body)
	}
}

func TestLinuxAlertInputIsRefused(t *testing.T) {
	_, cookie, e := readyGate(t)
	if w := apiCall(e.g, "GET", "/api/alerts", "", nil, "", true); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", w.Code)
	}
	if w := apiCall(e.g, "GET", "/api/alerts", "", cookie, "", false); w.Code != http.StatusForbidden {
		t.Fatalf("without the page header: %d", w.Code)
	}
	if w := apiCall(e.g, "GET", "/api/alerts/telegram", "", cookie, "", true); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET a change: %d", w.Code)
	}
	if w := apiCall(e.g, "POST", "/api/alerts/telegram", `{"token":"`+alertToken+`","chat_id":"42"}`, cookie, "https://evil.invalid", true); w.Code != http.StatusForbidden {
		t.Fatalf("another site: %d", w.Code)
	}
	for route, body := range map[string]string{
		"/api/alerts/telegram": `{"token":"` + alertToken + `","chat_id":"42","url":"https://evil.invalid"}`,
		"/api/alerts/remove":   `{"channel":"sms"}`,
		"/api/alerts/test":     `{"channel":"sms"}`,
	} {
		if w := apiCall(e.g, "POST", route, body, cookie, "https://"+localHost, true); w.Code != http.StatusBadRequest {
			t.Fatalf("%s %s: %d %s", route, body, w.Code, w.Body)
		}
	}
	for name, input := range map[string]map[string]any{
		"a bad token":        {"token": "not-a-token", "chat_id": "42"},
		"loopback mail":      {"host": "127.0.0.1", "port": 587, "security": "starttls", "from": "a@rootwell.test", "to": []string{"b@rootwell.test"}},
		"metadata mail":      {"host": "169.254.169.254", "port": 587, "security": "starttls", "from": "a@rootwell.test", "to": []string{"b@rootwell.test"}},
		"plain mail":         {"host": "mail.rootwell.test", "port": 25, "security": "none", "from": "a@rootwell.test", "to": []string{"b@rootwell.test"}},
		"a header in a name": {"host": "mail.rootwell.test", "port": 587, "security": "starttls", "from": "a@rootwell.test\r\nBcc: x@evil.invalid", "to": []string{"b@rootwell.test"}},
	} {
		route := "/api/alerts/email"
		if _, ok := input["token"]; ok {
			route = "/api/alerts/telegram"
		}
		w := post(t, e, cookie, route, input)
		var answer map[string]string
		if w.code != http.StatusBadRequest || json.Unmarshal(w.body, &answer) != nil || answer["error"] == "" {
			t.Fatalf("%s: %d %s", name, w.code, w.body)
		}
	}
	if _, out := alertSettings(t, e, cookie); out.Email != nil || out.Telegram != nil {
		t.Fatalf("refused input was kept: %+v", out)
	}
}

func TestLinuxATestNeedsAChannelAndWaitsBetweenTries(t *testing.T) {
	_, cookie, e := readyGate(t)
	w := post(t, e, cookie, "/api/alerts/test", map[string]any{"channel": "email"})
	var answer map[string]string
	if w.code != http.StatusConflict || json.Unmarshal(w.body, &answer) != nil || answer["error"] != "Save this channel first." {
		t.Fatalf("a test without a channel: %d %s", w.code, w.body)
	}
	if again := post(t, e, cookie, "/api/alerts/test", map[string]any{"channel": "telegram"}); again.code != http.StatusTooManyRequests || again.header.Get("Retry-After") != "10" {
		t.Fatalf("a second test at once: %d %s", again.code, again.body)
	}
	e.clock.add(testGap)
	if later := post(t, e, cookie, "/api/alerts/test", map[string]any{"channel": "telegram"}); later.code != http.StatusConflict {
		t.Fatalf("a test ten seconds later: %d %s", later.code, later.body)
	}
}
