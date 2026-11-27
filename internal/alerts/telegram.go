package alerts

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"
)

// Telegram sends alerts with a bot the person made with @BotFather, to one
// chat, group or channel. Rootwell connects to Telegram's own address only.
type Telegram struct {
	// Token is the bot's token. It is a secret: it is sealed in the vault and
	// never shown, logged or put in an error.
	Token string
	// ChatID is a numeric chat ID, or @name for a public channel.
	ChatID string
}

const telegramHost = "api.telegram.org"

var (
	telegramToken = regexp.MustCompile(`^[0-9]{5,16}:[A-Za-z0-9_-]{30,64}$`)
	telegramChat  = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)

	// ErrTelegramToken says the token is not one, or Telegram does not know it.
	ErrTelegramToken = errors.New("telegram does not accept this bot token")
	// ErrTelegramChat says the chat is wrong or the bot may not write there.
	ErrTelegramChat = errors.New("the bot cannot write to this chat")
	// ErrTelegramUnreachable says Telegram could not be reached.
	ErrTelegramUnreachable = errors.New("telegram could not be reached")
	// ErrTelegramRefused says Telegram answered with another refusal.
	ErrTelegramRefused = errors.New("telegram refused the message")
)

// Check says whether the token and chat look right, without sending.
func (t Telegram) Check() error {
	if !telegramToken.MatchString(t.Token) {
		return ErrTelegramToken
	}
	if !telegramChat.MatchString(t.ChatID) {
		return ErrTelegramChat
	}
	return nil
}

// telegramSender reaches one base address. Production uses Telegram's; tests
// use a local stand-in.
type telegramSender struct {
	base   string
	client *http.Client
}

func newTelegramSender() telegramSender {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		// No proxy from the environment, and only Telegram's address.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != telegramHost+":443" {
				return nil, ErrTelegramUnreachable
			}
			return dialer.DialContext(ctx, network, address)
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
	}
	return telegramSender{base: "https://" + telegramHost, client: &http.Client{
		Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// send posts one message. Errors are the ones above: never the URL, which
// holds the token, and never Telegram's own words.
func (s telegramSender) send(ctx context.Context, t Telegram, text string) error {
	if err := t.Check(); err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"chat_id": t.ChatID, "text": text, "disable_web_page_preview": true})
	if err != nil {
		return ErrTelegramRefused
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/bot"+t.Token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return ErrTelegramToken
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return ErrTelegramUnreachable
	}
	defer response.Body.Close()
	var answer struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil || json.Unmarshal(raw, &answer) != nil {
		return ErrTelegramRefused
	}
	switch {
	case answer.OK && response.StatusCode == http.StatusOK:
		return nil
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusNotFound:
		return ErrTelegramToken
	case response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusForbidden:
		return ErrTelegramChat
	}
	return ErrTelegramRefused
}
