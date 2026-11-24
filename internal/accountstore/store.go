// Package accountstore keeps the accounts that sign in to Rootwell in the
// vault (ADR 0088). Each account is one sealed record: its name, its password
// hash, its phone key, the last phone code it used and the digests of its
// recovery codes.
//
// A setup code, printed on the server by `rootwelld init` or
// `rootwelld setup-code`, is the only way to make an account or to replace a
// lost password or phone. An account is written only once its phone is
// confirmed, so there is never an account that signs in with a password
// alone.
package accountstore

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/rootwell/internal/account"
	"github.com/denyfirst/rootwell/internal/vault"
)

const (
	kindAccount = "account"
	kindSetup   = "setup"
	// MaxAccounts is how many accounts an installation has. The first release
	// has one administrator (ADR 0088); a setup code for a second is refused.
	MaxAccounts = 1
	// SetupLife is how long a setup code works.
	SetupLife  = 24 * time.Hour
	maxRecord  = 16 << 10
	timeLayout = time.RFC3339
)

var (
	// ErrRefused hides why a name, password or code was not accepted.
	ErrRefused = errors.New("not accepted")
	// ErrWeak says a new password is too short, too long, too common, or the
	// one it replaces.
	ErrWeak = errors.New("choose a different password")
	// ErrChanged says the account changed since the caller read it.
	ErrChanged = errors.New("the account changed")
	// ErrUnavailable hides a vault refusal: a damaged or unreadable record.
	ErrUnavailable = errors.New("the accounts could not be read")
)

// Account is what a page may know about an account.
type Account struct {
	Name         string
	Revision     uint64
	RecoveryLeft int
}

type accountRecord struct {
	Name      string               `json:"name"`
	Password  account.PasswordHash `json:"password"`
	Seed      string               `json:"seed"`
	LastStep  int64                `json:"last_step"`
	Recovery  [][]byte             `json:"recovery"`
	Revision  uint64               `json:"revision"`
	CreatedAt string               `json:"created_at"`
}

func (r accountRecord) public() Account {
	return Account{Name: r.Name, Revision: r.Revision, RecoveryLeft: len(r.Recovery)}
}

// setupRecord is the one setup code that works now. Account names the account
// whose sign-in it replaces; empty, it makes the first account.
type setupRecord struct {
	Digest  []byte `json:"digest"`
	Account string `json:"account,omitempty"`
	Until   string `json:"until"`
}

// Store reads and changes accounts. It is safe for concurrent use.
type Store struct {
	v     *vault.Store
	now   func() time.Time
	once  sync.Once
	dummy account.PasswordHash
}

// New uses an open vault and a clock: code checks and setup codes read it.
func New(v *vault.Store, now func() time.Time) *Store { return &Store{v: v, now: now} }

// Name turns what a person typed into an account name: letters are compared
// without case. It reports false for anything that cannot be a name.
func Name(typed string) (string, bool) {
	name := strings.ToLower(typed)
	return name, account.ValidName(name)
}

func decode(data []byte, v any) error {
	if len(data) == 0 || len(data) > maxRecord {
		return ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.More() {
		return ErrUnavailable
	}
	return nil
}

func put(t *vault.Tx, kind, id string, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > maxRecord {
		return ErrUnavailable
	}
	defer clear(data)
	if t.Put(kind, id, data) != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) accountID(name string) string { return s.v.Index(kindAccount, name) }
func (s *Store) setupID() string              { return s.v.Index(kindSetup, "setup") }

func (s *Store) readAccount(t *vault.Tx, name string) (accountRecord, error) {
	plain, _, err := t.Get(kindAccount, s.accountID(name))
	defer clear(plain)
	if errors.Is(err, vault.ErrMissing) {
		return accountRecord{}, ErrRefused
	}
	var r accountRecord
	if err != nil || decode(plain, &r) != nil || r.Name != name || r.Revision == 0 {
		return accountRecord{}, ErrUnavailable
	}
	return r, nil
}

func (s *Store) count(t *vault.Tx) (int, error) {
	ids, err := t.IDs(kindAccount)
	if err != nil {
		return 0, ErrUnavailable
	}
	return len(ids), nil
}

func (s *Store) readSetup(t *vault.Tx) (setupRecord, bool, error) {
	plain, _, err := t.Get(kindSetup, s.setupID())
	defer clear(plain)
	if errors.Is(err, vault.ErrMissing) {
		return setupRecord{}, false, nil
	}
	var r setupRecord
	if err != nil || decode(plain, &r) != nil || len(r.Digest) != 32 {
		return setupRecord{}, false, ErrUnavailable
	}
	return r, true, nil
}

// Exists reports whether any account has been made.
func (s *Store) Exists() (bool, error) {
	var n int
	err := s.v.View(func(t *vault.Tx) error {
		var err error
		n, err = s.count(t)
		return err
	})
	return n > 0, err
}

// Get reads one account.
func (s *Store) Get(name string) (Account, error) {
	var out Account
	err := s.v.View(func(t *vault.Tx) error {
		r, err := s.readAccount(t, name)
		out = r.public()
		return err
	})
	return out, err
}

// NewSetupCode replaces any earlier setup code with a new one that works for
// SetupLife. With an empty name it makes the first account, and is refused
// once one exists. With a name, it replaces that account's password and phone.
func (s *Store) NewSetupCode(name string) (string, time.Time, error) {
	key := s.v.CodeKey()
	defer clear(key)
	code, digest, err := account.NewBootstrapCode(key)
	if err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	until := s.now().UTC().Add(SetupLife).Truncate(time.Second)
	err = s.v.Update(func(t *vault.Tx) error {
		n, err := s.count(t)
		if err != nil {
			return err
		}
		if name == "" && n >= MaxAccounts {
			return ErrRefused
		}
		if name != "" {
			if _, err := s.readAccount(t, name); err != nil {
				return err
			}
		}
		return put(t, kindSetup, s.setupID(), setupRecord{Digest: digest, Account: name, Until: until.Format(timeLayout)})
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return code, until, nil
}

// setupFor checks a setup code and the name it is used with, inside t.
func (s *Store) setupFor(t *vault.Tx, code, name string) error {
	r, ok, err := s.readSetup(t)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRefused
	}
	until, err := time.Parse(timeLayout, r.Until)
	if err != nil {
		return ErrUnavailable
	}
	key := s.v.CodeKey()
	defer clear(key)
	if len(code) == 0 || len(code) > 64 ||
		subtle.ConstantTimeCompare(account.CodeDigest(key, code), r.Digest) != 1 || !s.now().Before(until) {
		return ErrRefused
	}
	if r.Account != "" {
		if r.Account != name {
			return ErrRefused
		}
		_, err := s.readAccount(t, name)
		return err
	}
	n, err := s.count(t)
	if err != nil {
		return err
	}
	if n >= MaxAccounts {
		return ErrRefused
	}
	return nil
}

// CheckSetup says whether code is the setup code that works now, for name.
// It changes nothing.
func (s *Store) CheckSetup(code, name string) error {
	return s.v.View(func(t *vault.Tx) error { return s.setupFor(t, code, name) })
}

// FinishSetup makes the account the setup code is for, or replaces its
// password and phone, and spends the code, all in one write. step is the
// phone code step that confirmed seed. It returns the account's ten new
// recovery codes; earlier ones stop working.
func (s *Store) FinishSetup(code, name string, password account.PasswordHash, seed string, step int64) ([]string, Account, error) {
	key := s.v.CodeKey()
	defer clear(key)
	codes, digests, err := account.NewRecoveryCodes(key)
	if err != nil {
		return nil, Account{}, ErrUnavailable
	}
	var out Account
	err = s.v.Update(func(t *vault.Tx) error {
		if err := s.setupFor(t, code, name); err != nil {
			return err
		}
		r, err := s.readAccount(t, name)
		switch {
		case errors.Is(err, ErrRefused):
			r = accountRecord{Name: name, CreatedAt: s.now().UTC().Format(timeLayout)}
		case err != nil:
			return err
		}
		r.Password, r.Seed, r.LastStep, r.Recovery = password, seed, step, digests
		r.Revision++
		if err := put(t, kindAccount, s.accountID(name), r); err != nil {
			return err
		}
		if t.Delete(kindSetup, s.setupID()) != nil {
			return ErrUnavailable
		}
		out = r.public()
		return nil
	})
	if err != nil {
		return nil, Account{}, err
	}
	return codes, out, nil
}

// dummyHash is checked against when a name is unknown, so a wrong name costs
// the same work as a wrong password and says nothing about which names exist.
func (s *Store) dummyHash() account.PasswordHash {
	s.once.Do(func() {
		s.dummy, _ = account.HashPassword("rootwell unknown account placeholder")
	})
	return s.dummy
}

// CheckPassword checks a name and its password.
func (s *Store) CheckPassword(name, password string) (Account, error) {
	var r accountRecord
	err := s.v.View(func(t *vault.Tx) error {
		var err error
		r, err = s.readAccount(t, name)
		return err
	})
	if errors.Is(err, ErrRefused) {
		s.dummyHash().Verify(password)
		return Account{}, ErrRefused
	}
	if err != nil {
		return Account{}, err
	}
	if !r.Password.Verify(password) {
		return Account{}, ErrRefused
	}
	return r.public(), nil
}

// sixDigits tells a phone code from a recovery code.
func sixDigits(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// UseCode accepts a phone code or a recovery code for an account still at
// revision. Each works once: the phone code's step is kept, and a recovery
// code is taken off the list.
func (s *Store) UseCode(name string, revision uint64, code string) (Account, error) {
	var out Account
	err := s.v.Update(func(t *vault.Tx) error {
		r, err := s.readAccount(t, name)
		if err != nil {
			return err
		}
		if r.Revision != revision {
			return ErrChanged
		}
		if sixDigits(code) {
			step, ok := account.CheckCode(r.Seed, code, s.now(), r.LastStep)
			if !ok {
				return ErrRefused
			}
			r.LastStep = step
		} else {
			key := s.v.CodeKey()
			defer clear(key)
			rest, ok := account.UseRecoveryCode(key, code, r.Recovery)
			if !ok {
				return ErrRefused
			}
			r.Recovery = rest
		}
		if err := put(t, kindAccount, s.accountID(name), r); err != nil {
			return err
		}
		out = r.public()
		return nil
	})
	return out, err
}

// change rewrites an account still at revision, and counts one revision:
// every session made before it ends.
func (s *Store) change(name string, revision uint64, fn func(*accountRecord) error) (Account, error) {
	var out Account
	err := s.v.Update(func(t *vault.Tx) error {
		r, err := s.readAccount(t, name)
		if err != nil {
			return err
		}
		if r.Revision != revision {
			return ErrChanged
		}
		if err := fn(&r); err != nil {
			return err
		}
		r.Revision++
		if err := put(t, kindAccount, s.accountID(name), r); err != nil {
			return err
		}
		out = r.public()
		return nil
	})
	return out, err
}

// ChangePassword replaces the password once the current one is checked. The
// slow work runs before the write, so the vault is never held for it.
func (s *Store) ChangePassword(name string, revision uint64, current, next string) (Account, error) {
	if current == next || account.CheckNewPassword(next) != nil {
		return Account{}, ErrWeak
	}
	a, err := s.CheckPassword(name, current)
	if err != nil {
		return Account{}, err
	}
	if a.Revision != revision {
		return Account{}, ErrChanged
	}
	hash, err := account.HashPassword(next)
	if err != nil {
		return Account{}, ErrWeak
	}
	return s.change(name, revision, func(r *accountRecord) error {
		r.Password = hash
		return nil
	})
}

// ReplacePhone keeps a new phone key that step confirmed. The old phone's
// codes stop working; the recovery codes stay.
func (s *Store) ReplacePhone(name string, revision uint64, seed string, step int64) (Account, error) {
	return s.change(name, revision, func(r *accountRecord) error {
		r.Seed, r.LastStep = seed, step
		return nil
	})
}

// NewRecoveryCodes replaces every recovery code with ten new ones.
func (s *Store) NewRecoveryCodes(name string, revision uint64) ([]string, Account, error) {
	key := s.v.CodeKey()
	defer clear(key)
	codes, digests, err := account.NewRecoveryCodes(key)
	if err != nil {
		return nil, Account{}, ErrUnavailable
	}
	a, err := s.change(name, revision, func(r *accountRecord) error {
		r.Recovery = digests
		return nil
	})
	if err != nil {
		return nil, Account{}, err
	}
	return codes, a, nil
}
