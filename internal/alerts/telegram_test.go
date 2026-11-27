package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "123456789:AAH-synthetic_token_for_tests_only_000"

func TestTelegramSendsOneMessageToTheChat(t *testing.T) {
	var got map[string]any
	var path string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer server.Close()
	s := testTelegram(server)
	if err := s.send(context.Background(), Telegram{Token: testToken, ChatID: "-1001234567890"}, "shop.test ends in 14 days"); err != nil {
		t.Fatal(err)
	}
	if path != "/bot"+testToken+"/sendMessage" || got["chat_id"] != "-1001234567890" || got["text"] != "shop.test ends in 14 days" || got["disable_web_page_preview"] != true {
		t.Fatalf("sent %s %v", path, got)
	}
}

func TestTelegramRefusalsAreNamedWithoutTheToken(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{401, `{"ok":false,"error_code":401,"description":"Unauthorized"}`, ErrTelegramToken},
		{404, `{"ok":false,"error_code":404,"description":"Not Found"}`, ErrTelegramToken},
		{400, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`, ErrTelegramChat},
		{403, `{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`, ErrTelegramChat},
		{429, `{"ok":false,"error_code":429,"description":"Too Many Requests"}`, ErrTelegramRefused},
		{302, ``, ErrTelegramRefused},
		{200, `not json`, ErrTelegramRefused},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.status == 302 {
				http.Redirect(w, r, "https://elsewhere.invalid/", http.StatusFound)
				return
			}
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		err := testTelegram(server).send(context.Background(), Telegram{Token: testToken, ChatID: "42"}, "x")
		server.Close()
		if !errors.Is(err, tc.want) || strings.Contains(err.Error(), "AAH-") || strings.Contains(Explain(err), "AAH-") {
			t.Fatalf("%d: %v", tc.status, err)
		}
	}
	// A server that is gone: the error names Telegram, never the address
	// with the token in it.
	server := httptest.NewTLSServer(http.NotFoundHandler())
	s := testTelegram(server)
	server.Close()
	if err := s.send(context.Background(), Telegram{Token: testToken, ChatID: "42"}, "x"); !errors.Is(err, ErrTelegramUnreachable) || strings.Contains(err.Error(), "AAH-") {
		t.Fatalf("unreachable: %v", err)
	}
}

func TestTelegramSettingsAreCheckedBeforeSending(t *testing.T) {
	sent := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sent = true }))
	defer server.Close()
	s := testTelegram(server)
	for _, tg := range []Telegram{
		{Token: "not-a-token", ChatID: "42"},
		{Token: testToken + "/../x", ChatID: "42"},
		{Token: testToken, ChatID: "42?x=1"},
		{Token: testToken, ChatID: ""},
		{Token: testToken, ChatID: "@ab"},
	} {
		if err := s.send(context.Background(), tg, "x"); err == nil {
			t.Fatalf("%+v was sent", tg)
		}
	}
	if sent {
		t.Fatal("a malformed setting reached Telegram")
	}
	for _, chat := range []string{"42", "-1001234567890", "@rootwell_alerts"} {
		if err := (Telegram{Token: testToken, ChatID: chat}).Check(); err != nil {
			t.Fatalf("%s: %v", chat, err)
		}
	}
}

func TestTelegramConnectsOnlyToTelegram(t *testing.T) {
	transport := newTelegramSender().client.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("a proxy from the environment would see every message")
	}
	for _, address := range []string{"elsewhere.invalid:443", "api.telegram.org:80", "127.0.0.1:443", "api.telegram.org.evil.invalid:443"} {
		if _, err := transport.DialContext(context.Background(), "tcp", address); !errors.Is(err, ErrTelegramUnreachable) {
			t.Fatalf("%s: %v", address, err)
		}
	}
	if newTelegramSender().client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects are followed")
	}
}

// testTelegram reaches a local stand-in with the production sender's rules
// for redirects.
func testTelegram(server *httptest.Server) telegramSender {
	client := server.Client()
	client.CheckRedirect = newTelegramSender().client.CheckRedirect
	return telegramSender{base: server.URL, client: client}
}
