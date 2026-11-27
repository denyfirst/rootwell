package main

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/alerts"
)

// testGap is the least time between two test messages; one runs at a time.
const testGap = 10 * time.Second

type alertsOutput struct {
	Email    *alerts.EmailSettings    `json:"email"`
	Telegram *alerts.TelegramSettings `json:"telegram"`
	Log      []alerts.Entry           `json:"log"`
}

type emailInput struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Security     string   `json:"security"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	KeepPassword bool     `json:"keep_password"`
	From         string   `json:"from"`
	To           []string `json:"to"`
}

type telegramInput struct {
	Token     string `json:"token"`
	KeepToken bool   `json:"keep_token"`
	ChatID    string `json:"chat_id"`
}

type channelInput struct {
	Channel string `json:"channel"`
}

// alertsEndpoint shows the alert settings (GET /api/alerts) and changes them.
// Saving a channel, which keeps a secret, and turning one off need a fresh
// code, so a stolen session can neither redirect alerts nor silence them. A
// test message needs only a signed-in session.
func (g *gate) alertsEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.URL.Path == "/api/alerts" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		if !signedIn {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Rootwell-Request") != "1" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "request origin refused", http.StatusForbidden)
			return
		}
		settings, state, err := g.alertStore.Settings()
		if err != nil {
			http.Error(w, "the alert settings could not be read", http.StatusServiceUnavailable)
			return
		}
		log := state.Log
		if log == nil {
			log = []alerts.Entry{}
		}
		writeJSON(w, http.StatusOK, alertsOutput{Email: settings.Email, Telegram: settings.Telegram, Log: log})
		return
	}
	if !signedIn {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if !g.post(w, r) {
		return
	}
	var err error
	switch r.URL.Path {
	case "/api/alerts/email":
		var input emailInput
		if !readJSON(w, r, &input) {
			return
		}
		if !s.isFresh(g.now()) {
			needFresh(w)
			return
		}
		err = g.alertStore.SetEmail(alerts.Email{Host: strings.TrimSpace(input.Host), Port: input.Port, Security: input.Security,
			Username: input.Username, Password: input.Password, From: strings.TrimSpace(input.From), To: input.To}, input.KeepPassword)
	case "/api/alerts/telegram":
		var input telegramInput
		if !readJSON(w, r, &input) {
			return
		}
		if !s.isFresh(g.now()) {
			needFresh(w)
			return
		}
		err = g.alertStore.SetTelegram(alerts.Telegram{Token: strings.TrimSpace(input.Token), ChatID: strings.TrimSpace(input.ChatID)}, input.KeepToken)
	case "/api/alerts/remove":
		var input channelInput
		if !readJSON(w, r, &input) {
			return
		}
		if input.Channel != "email" && input.Channel != "telegram" {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if !s.isFresh(g.now()) {
			needFresh(w)
			return
		}
		err = g.alertStore.Remove(input.Channel)
	case "/api/alerts/test":
		g.alertTest(w, r, s)
		return
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		if errors.Is(err, alerts.ErrUnavailable) {
			http.Error(w, "the alert settings could not be read", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": alerts.Explain(err)})
		return
	}
	if !g.stillReady(r, s) {
		http.Error(w, "Saved, but this session ended. Sign in again.", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// alertTest sends one test message on one channel, one at a time and at
// most one every ten seconds, and says how it went.
func (g *gate) alertTest(w http.ResponseWriter, r *http.Request, s session) {
	var input channelInput
	if !readJSON(w, r, &input) {
		return
	}
	if input.Channel != "email" && input.Channel != "telegram" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	now := g.now()
	if g.alertBusy || (!g.alertLast.IsZero() && now.Sub(g.alertLast) < testGap) {
		g.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(int(testGap/time.Second)))
		http.Error(w, "A test was just sent. Try again in a few seconds.", http.StatusTooManyRequests)
		return
	}
	g.alertBusy, g.alertLast = true, now
	g.mu.Unlock()
	defer func() { g.mu.Lock(); g.alertBusy = false; g.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	err := g.alerts.Test(ctx, input.Channel)
	if !g.stillReady(r, s) {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
	case errors.Is(err, alerts.ErrNoChannel):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Save this channel first."})
	case errors.Is(err, alerts.ErrUnavailable):
		http.Error(w, "the alert settings could not be read", http.StatusServiceUnavailable)
	default:
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
	}
}

// alertCertificates are what alerts are about: the saved certificates that
// were not replaced by a newer one.
func (g *gate) alertCertificates() ([]alerts.Certificate, error) {
	records, _, err := g.certificates.List()
	if err != nil {
		return nil, err
	}
	out := make([]alerts.Certificate, 0, len(records))
	for _, r := range records {
		if r.ReplacedBy != "" {
			continue
		}
		end, err := time.Parse(time.RFC3339, r.NotAfter)
		if err != nil {
			continue
		}
		name := ""
		if c, err := x509.ParseCertificate(r.DER); err == nil {
			name = c.Subject.CommonName
			if name == "" && len(c.DNSNames) > 0 {
				name = c.DNSNames[0]
			}
			if name == "" && len(c.IPAddresses) > 0 {
				name = c.IPAddresses[0].String()
			}
		}
		if name == "" {
			name = "A certificate"
		}
		out = append(out, alerts.Certificate{Fingerprint: r.Fingerprint, Name: name, NotAfter: end, Places: append([]string{}, r.Locations...), Owner: r.Owner})
	}
	return out, nil
}

// alertRoots verify a mail server: the public roots and the authorities saved
// in Certificates, as Website check's do.
func (g *gate) alertRoots() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, root := range g.savedRoots() {
		pool.AddCert(root)
	}
	return pool
}

// alertLink is the address of a certificate's sheet, on the first name
// Rootwell answers to that is not loopback; "" when it has none.
func alertLink(host string) func(string) string {
	if host == "" {
		return func(string) string { return "" }
	}
	return func(fingerprint string) string {
		return "https://" + host + "/certificates#" + strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	}
}
