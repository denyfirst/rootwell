package alerts

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/vault"
)

func newTestStore(t *testing.T) (*Store, *vault.Store) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the vault opens only in a private Linux directory")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := vault.NewInstanceKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Create(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return NewStore(v), v
}

func TestTheSecretsAreKeptApartAndNeverShown(t *testing.T) {
	s, v := newTestStore(t)
	mail := settings("starttls", 587)
	if err := s.SetEmail(mail, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTelegram(Telegram{Token: testToken, ChatID: "42"}, false); err != nil {
		t.Fatal(err)
	}
	shown, _, err := s.Settings()
	if err != nil {
		t.Fatal(err)
	}
	listed, _ := json.Marshal(shown)
	if strings.Contains(string(listed), mail.Password) || strings.Contains(string(listed), "AAH-") || !shown.Email.HasPassword || shown.Telegram.ChatID != "42" {
		t.Fatalf("the settings show %s", listed)
	}
	if err := v.View(func(t *vault.Tx) error {
		plain, _, err := t.Get(kindSettings, s.id(kindSettings))
		if err != nil || strings.Contains(string(plain), mail.Password) || strings.Contains(string(plain), "AAH-") {
			return errors.New("the settings record holds a secret")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The page sends no password back: keeping it keeps the one stored.
	changed := mail
	changed.Password, changed.To = "", []string{"night@rootwell.test"}
	if err := s.SetEmail(changed, true); err != nil {
		t.Fatal(err)
	}
	email, telegram, err := s.channels()
	if err != nil || email.Password != mail.Password || email.To[0] != "night@rootwell.test" || telegram.Token != testToken {
		t.Fatalf("channels: %+v %+v %v", email, telegram, err)
	}
	// Keeping a password that was never stored, or sending one while keeping,
	// is refused and changes nothing.
	changed.Password = "another"
	if err := s.SetEmail(changed, true); !errors.Is(err, ErrEmailSettings) {
		t.Fatalf("keep and send a password: %v", err)
	}
	if err := s.SetTelegram(Telegram{ChatID: "not a chat"}, true); err == nil {
		t.Fatal("a bad chat was kept")
	}
	if err := s.Remove("telegram"); err != nil {
		t.Fatal(err)
	}
	if _, telegram, _ := s.channels(); telegram != nil {
		t.Fatal("a removed channel still sends")
	}
	if err := v.View(func(t *vault.Tx) error {
		plain, _, err := t.Get(kindSecrets, s.id(kindSecrets))
		if err != nil || strings.Contains(string(plain), "AAH-") || !strings.Contains(string(plain), mail.Password) {
			return errors.New("turning Telegram off did not forget only its token")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTelegram(Telegram{ChatID: "42"}, true); err == nil {
		t.Fatal("a removed token was kept")
	}
}

func TestAlertRecordsAreReadStrictly(t *testing.T) {
	s, v := newTestStore(t)
	if err := s.SetTelegram(Telegram{Token: testToken, ChatID: "42"}, false); err != nil {
		t.Fatal(err)
	}
	if err := v.Update(func(t *vault.Tx) error {
		return t.Put(kindSettings, s.id(kindSettings), []byte(`{"telegram":{"chat_id":"42","url":"https://elsewhere.invalid"}}`))
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Settings(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a record with an unknown field was read: %v", err)
	}
}

// telegramStandIn counts the messages Telegram would get, and can be down.
type telegramStandIn struct {
	mu       sync.Mutex
	messages []string
	down     bool
}

func (f *telegramStandIn) start(t *testing.T) telegramSender {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.down {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"ok":false,"error_code":502}`))
			return
		}
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		f.messages = append(f.messages, body["text"].(string))
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)
	return testTelegram(server)
}

func TestAlertsGoOutOnceAndRetryWhenNothingArrived(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.SetTelegram(Telegram{Token: testToken, ChatID: "42"}, false); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	listed := []Certificate{
		{Fingerprint: "AA", Name: "shop.test", NotAfter: now.Add(13 * day), Places: []string{"web-1"}, Owner: "Web team"},
		{Fingerprint: "BB", Name: "mail.test\r\nBcc: x@evil.invalid", NotAfter: now.Add(-2 * day)},
		{Fingerprint: "CC", Name: "far.test", NotAfter: now.Add(200 * day)},
	}
	f := &telegramStandIn{down: true}
	service := &Service{store: s, certificates: func() ([]Certificate, error) { return listed, nil }, roots: x509.NewCertPool,
		link: func(fp string) string { return "https://rootwell.lab.test:4180/certificates#" + strings.ToLower(fp) }, now: func() time.Time { return now },
		telegram: f.start(t)}
	// Telegram is down: nothing is recorded as sent, and the log says why.
	if err := service.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, state, _ := s.Settings()
	if len(state.Sent) != 0 || len(state.Log) != 1 || state.Log[0].Results["telegram"] != Explain(ErrTelegramRefused) {
		t.Fatalf("a failed send: %+v", state)
	}
	f.down = false
	if err := service.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.messages) != 1 {
		t.Fatalf("%d messages", len(f.messages))
	}
	text := f.messages[0]
	for _, want := range []string{"Rootwell: 2 certificates need attention", "mail.test  Bcc: x@evil.invalid expired on 25 Nov 2026.",
		"shop.test ends in 13 days, on 10 Dec 2026.\nUsed on: web-1\nOwner: Web team\nhttps://rootwell.lab.test:4180/certificates#aa"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the message lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "far.test") || strings.Contains(text, "\r") {
		t.Fatalf("the message:\n%s", text)
	}
	// Once sent, a step is not sent again; the next step is.
	if err := service.Run(context.Background()); err != nil || len(f.messages) != 1 {
		t.Fatalf("sent again: %d %v", len(f.messages), err)
	}
	now = now.Add(7 * day)
	if err := service.Run(context.Background()); err != nil || len(f.messages) != 2 || !strings.HasPrefix(f.messages[1], "Rootwell: shop.test ends in 6 days") {
		t.Fatalf("the 7-day step: %v %q", err, f.messages)
	}
	_, state, _ = s.Settings()
	if len(state.Log) != 3 || state.Log[0].Results["telegram"] != "" {
		t.Fatalf("the log: %+v", state.Log)
	}
	// A test message goes out on the channel asked for, and is logged as one.
	if err := service.Test(context.Background(), "telegram"); err != nil || len(f.messages) != 3 {
		t.Fatalf("test: %v", err)
	}
	if err := service.Test(context.Background(), "email"); !errors.Is(err, ErrNoChannel) {
		t.Fatalf("a test on a channel not set up: %v", err)
	}
	f.down = true
	if err := service.Test(context.Background(), "telegram"); err == nil || err.Error() != Explain(ErrTelegramRefused) {
		t.Fatalf("a failed test: %v", err)
	}
}

func TestNoChannelSendsNothing(t *testing.T) {
	s, _ := newTestStore(t)
	called := false
	service := &Service{store: s, certificates: func() ([]Certificate, error) { called = true; return nil, nil }, now: time.Now}
	if err := service.Run(context.Background()); err != nil || called {
		t.Fatalf("without a channel: %v, listed %v", err, called)
	}
}
