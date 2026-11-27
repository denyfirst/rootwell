package alerts

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/denyfirst/rootwell/internal/vault"
)

// The alert settings live in the vault as three sealed records: what the page
// shows, the secrets it never shows (the mail password and the bot token), and
// what was sent. Reading the settings never opens the secrets.
const (
	kindSettings = "alert-settings"
	kindSecrets  = "alert-secrets"
	kindState    = "alert-state"
	// maxLog is how many past sends the page lists.
	maxLog = 20
)

// ErrUnavailable hides a vault refusal: a damaged or unreadable record.
var ErrUnavailable = errors.New("the alert settings could not be read")

// Settings is what the page shows: every setting but the secrets.
type Settings struct {
	Email    *EmailSettings    `json:"email,omitempty"`
	Telegram *TelegramSettings `json:"telegram,omitempty"`
}

// EmailSettings is Email without its password.
type EmailSettings struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Security string   `json:"security"`
	Username string   `json:"username,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	// HasPassword says a password is kept.
	HasPassword bool `json:"has_password"`
}

// TelegramSettings is Telegram without its token.
type TelegramSettings struct {
	ChatID string `json:"chat_id"`
}

type secrets struct {
	EmailPassword string `json:"email_password,omitempty"`
	TelegramToken string `json:"telegram_token,omitempty"`
}

// State is what was sent: per certificate, and the last sends for the page.
type State struct {
	Sent Sent    `json:"sent"`
	Log  []Entry `json:"log"`
}

// Entry is one send: when, what it was about, and how each channel did.
type Entry struct {
	At      time.Time `json:"at"`
	Subject string    `json:"subject"`
	Test    bool      `json:"test,omitempty"`
	// Results maps "email" or "telegram" to "" when it was delivered, or the
	// sentence Explain gives.
	Results map[string]string `json:"results"`
}

// Store reads and changes the alert settings in the vault.
type Store struct{ v *vault.Store }

// NewStore uses an open vault.
func NewStore(v *vault.Store) *Store { return &Store{v: v} }

func (s *Store) id(kind string) string { return s.v.Index(kind, kind) }

func strict(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data")
	}
	return nil
}

// get reads one record into v; a missing record leaves v as it is.
func (s *Store) get(t *vault.Tx, kind string, v any) error {
	plain, _, err := t.Get(kind, s.id(kind))
	defer clear(plain)
	if errors.Is(err, vault.ErrMissing) {
		return nil
	}
	if err != nil || strict(plain, v) != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) put(t *vault.Tx, kind string, v any) error {
	plain, err := json.Marshal(v)
	defer clear(plain)
	if err != nil || t.Put(kind, s.id(kind), plain) != nil {
		return ErrUnavailable
	}
	return nil
}

// Settings reads what the page shows. No secret is opened.
func (s *Store) Settings() (Settings, State, error) {
	var settings Settings
	var state State
	err := s.v.View(func(t *vault.Tx) error {
		if err := s.get(t, kindSettings, &settings); err != nil {
			return err
		}
		return s.get(t, kindState, &state)
	})
	return settings, state, err
}

// channels opens the settings with their secrets, for one send.
func (s *Store) channels() (*Email, *Telegram, error) {
	var settings Settings
	var keep secrets
	err := s.v.View(func(t *vault.Tx) error {
		if err := s.get(t, kindSettings, &settings); err != nil {
			return err
		}
		return s.get(t, kindSecrets, &keep)
	})
	if err != nil {
		return nil, nil, err
	}
	var email *Email
	var telegram *Telegram
	if e := settings.Email; e != nil {
		email = &Email{Host: e.Host, Port: e.Port, Security: e.Security, Username: e.Username, Password: keep.EmailPassword, From: e.From, To: slices.Clone(e.To)}
	}
	if settings.Telegram != nil && keep.TelegramToken != "" {
		telegram = &Telegram{Token: keep.TelegramToken, ChatID: settings.Telegram.ChatID}
	}
	return email, telegram, nil
}

// change reads the settings and secrets, lets edit change them, and writes
// both back in one transaction.
func (s *Store) change(edit func(*Settings, *secrets) error) error {
	return s.v.Update(func(t *vault.Tx) error {
		var settings Settings
		var keep secrets
		if err := s.get(t, kindSettings, &settings); err != nil {
			return err
		}
		if err := s.get(t, kindSecrets, &keep); err != nil {
			return err
		}
		if err := edit(&settings, &keep); err != nil {
			return err
		}
		if err := s.put(t, kindSettings, settings); err != nil {
			return err
		}
		return s.put(t, kindSecrets, keep)
	})
}

// SetEmail keeps the mail settings. With keepPassword, the password kept
// before stays; the page never has it to send back.
func (s *Store) SetEmail(e Email, keepPassword bool) error {
	return s.change(func(settings *Settings, keep *secrets) error {
		if keepPassword {
			if settings.Email == nil || !settings.Email.HasPassword || e.Password != "" {
				return ErrEmailSettings
			}
			e.Password = keep.EmailPassword
		}
		if err := e.Check(); err != nil {
			return err
		}
		settings.Email = &EmailSettings{Host: e.Host, Port: e.Port, Security: e.Security, Username: e.Username, From: e.From, To: slices.Clone(e.To), HasPassword: e.Password != ""}
		keep.EmailPassword = e.Password
		return nil
	})
}

// SetTelegram keeps the Telegram settings. With keepToken, the token kept
// before stays.
func (s *Store) SetTelegram(tg Telegram, keepToken bool) error {
	return s.change(func(settings *Settings, keep *secrets) error {
		if keepToken {
			if settings.Telegram == nil || keep.TelegramToken == "" || tg.Token != "" {
				return ErrTelegramToken
			}
			tg.Token = keep.TelegramToken
		}
		if err := tg.Check(); err != nil {
			return err
		}
		settings.Telegram = &TelegramSettings{ChatID: tg.ChatID}
		keep.TelegramToken = tg.Token
		return nil
	})
}

// Remove turns a channel off and forgets its secret.
func (s *Store) Remove(channel string) error {
	return s.change(func(settings *Settings, keep *secrets) error {
		switch channel {
		case "email":
			settings.Email, keep.EmailPassword = nil, ""
		case "telegram":
			settings.Telegram, keep.TelegramToken = nil, ""
		default:
			return ErrUnavailable
		}
		return nil
	})
}

// record keeps what was sent: the steps per certificate, and one more line
// in the log, which keeps the latest maxLog.
func (s *Store) record(sent Sent, entry *Entry) error {
	return s.v.Update(func(t *vault.Tx) error {
		var state State
		if err := s.get(t, kindState, &state); err != nil {
			return err
		}
		if sent != nil {
			state.Sent = sent
		}
		if entry != nil {
			state.Log = append([]Entry{*entry}, state.Log...)
			if len(state.Log) > maxLog {
				state.Log = state.Log[:maxLog]
			}
		}
		return s.put(t, kindState, state)
	})
}
