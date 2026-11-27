package alerts

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ErrNoChannel says no channel is set up, or not the one asked for.
var ErrNoChannel = errors.New("no alert channel is set up")

// Service decides what is due and sends it on every channel set up. One send
// runs at a time.
type Service struct {
	store *Store
	// certificates lists the certificates alerts are about: the saved ones
	// that are not replaced.
	certificates func() ([]Certificate, error)
	// roots verifies a mail server: the public roots and the authorities
	// saved in Certificates.
	roots func() *x509.CertPool
	// link is the address of a certificate's sheet, or "".
	link     func(fingerprint string) string
	now      func() time.Time
	email    emailSender
	telegram telegramSender
	mu       sync.Mutex
}

// NewService sends through the real networks.
func NewService(store *Store, certificates func() ([]Certificate, error), roots func() *x509.CertPool, link func(string) string) *Service {
	return &Service{store: store, certificates: certificates, roots: roots, link: link, now: time.Now,
		email: newEmailSender(), telegram: newTelegramSender()}
}

// Run sends what is due now. It records a step as sent when at least one
// channel delivered it, so a channel that is down does not repeat the other
// one's messages; when none delivered, the next run tries again.
func (s *Service) Run(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	email, telegram, err := s.store.channels()
	if err != nil {
		return err
	}
	if email == nil && telegram == nil {
		return nil
	}
	defer forget(email, telegram)
	_, state, err := s.store.Settings()
	if err != nil {
		return err
	}
	listed, err := s.certificates()
	if err != nil {
		return err
	}
	now := s.now()
	due := Due(listed, state.Sent, now)
	if len(due) == 0 {
		return s.store.record(Remember(state.Sent, nil, listed), nil)
	}
	subject, text := s.compose(due)
	entry := s.deliver(ctx, email, telegram, subject, text, now)
	delivered := false
	for _, result := range entry.Results {
		delivered = delivered || result == ""
	}
	if !delivered {
		return s.store.record(nil, &entry)
	}
	return s.store.record(Remember(state.Sent, due, listed), &entry)
}

// Notify sends one message about something other than a certificate's end,
// such as a watched website, on every channel set up, and logs it. With no
// channel set up it sends nothing.
func (s *Service) Notify(ctx context.Context, subject, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	email, telegram, err := s.store.channels()
	if err != nil {
		return err
	}
	if email == nil && telegram == nil {
		return nil
	}
	defer forget(email, telegram)
	entry := s.deliver(ctx, email, telegram, plain(subject), text, s.now())
	return s.store.record(nil, &entry)
}

// Test sends a short message on one channel now, and says how it went.
func (s *Service) Test(ctx context.Context, channel string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	email, telegram, err := s.store.channels()
	if err != nil {
		return err
	}
	defer forget(email, telegram)
	switch channel {
	case "email":
		telegram = nil
	case "telegram":
		email = nil
	default:
		return ErrNoChannel
	}
	if email == nil && telegram == nil {
		return ErrNoChannel
	}
	now := s.now()
	subject := "Rootwell: a test alert"
	text := "This is a test from Rootwell. Alerts about certificates come here, 30, 14 and 7 days before one ends, and on the day it ends."
	entry := s.deliver(ctx, email, telegram, subject, text, now)
	entry.Test = true
	if err := s.store.record(nil, &entry); err != nil {
		return err
	}
	if result := entry.Results[channel]; result != "" {
		return errors.New(result)
	}
	return nil
}

func (s *Service) deliver(ctx context.Context, email *Email, telegram *Telegram, subject, text string, now time.Time) Entry {
	entry := Entry{At: now.UTC(), Subject: subject, Results: map[string]string{}}
	if email != nil {
		entry.Results["email"] = ""
		if err := s.email.send(ctx, *email, s.roots(), subject, text, now); err != nil {
			entry.Results["email"] = Explain(err)
		}
	}
	if telegram != nil {
		entry.Results["telegram"] = ""
		if err := s.telegram.send(ctx, *telegram, subject+"\n\n"+text); err != nil {
			entry.Results["telegram"] = Explain(err)
		}
	}
	return entry
}

// forget drops the secrets opened for one send.
func forget(email *Email, telegram *Telegram) {
	if email != nil {
		email.Password = ""
	}
	if telegram != nil {
		telegram.Token = ""
	}
}

func dateOf(t time.Time) string { return t.UTC().Format("2 Jan 2006") }

// what says, in a few words, where a certificate stands.
func what(a Alert) string {
	switch {
	case a.Step == 0:
		return "has expired"
	case a.DaysLeft == 1:
		return "ends tomorrow"
	}
	return fmt.Sprintf("ends in %d days", a.DaysLeft)
}

// plain makes text from a certificate safe for one line of a message: no
// control characters, and at most 200 characters.
func plain(text string) string {
	out := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, text)
	if runes := []rune(out); len(runes) > 200 {
		out = string(runes[:200]) + "…"
	}
	return strings.TrimSpace(out)
}

// compose writes one message for everything due, soonest first.
func (s *Service) compose(due []Alert) (string, string) {
	subject := "Rootwell: " + plain(due[0].Certificate.Name) + " " + what(due[0])
	if len(due) > 1 {
		subject = fmt.Sprintf("Rootwell: %d certificates need attention", len(due))
	}
	var b strings.Builder
	for i, a := range due {
		if i > 0 {
			b.WriteString("\n")
		}
		c := a.Certificate
		c.Name, c.Owner = plain(c.Name), plain(c.Owner)
		places := make([]string, len(c.Places))
		for i := range c.Places {
			places[i] = plain(c.Places[i])
		}
		c.Places = places
		if a.Step == 0 {
			b.WriteString(c.Name + " expired on " + dateOf(c.NotAfter) + ".\n")
		} else {
			b.WriteString(c.Name + " " + what(a) + ", on " + dateOf(c.NotAfter) + ".\n")
		}
		if len(c.Places) > 0 {
			b.WriteString("Used on: " + strings.Join(c.Places, ", ") + "\n")
		}
		if c.Owner != "" {
			b.WriteString("Owner: " + c.Owner + "\n")
		}
		if link := s.link(c.Fingerprint); link != "" {
			b.WriteString(link + "\n")
		}
	}
	b.WriteString("\nRootwell sends this 30, 14 and 7 days before a certificate ends, and on the day it ends.")
	return subject, b.String()
}
