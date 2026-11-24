package accountstore

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 fixes HMAC-SHA1; this test computes phone codes independently.
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/account"
	"github.com/denyfirst/rootwell/internal/vault"
)

const (
	firstPassword = "correct horse battery staple, twice"
	nextPassword  = "a different passphrase for the test"
)

type clock struct{ at time.Time }

func (c *clock) now() time.Time { return c.at }

func newStore(t *testing.T) (*Store, *vault.Store, *clock, string) {
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
	c := &clock{at: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	s := New(v)
	s.now = c.now
	return s, v, c, dir
}

// code computes an RFC 6238 phone code apart from the package under test.
func code(t *testing.T, seed string, at time.Time) string {
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

func step(at time.Time) int64 { return at.Unix() / 30 }

// setUp makes the first account through a setup code, as the pages do.
func setUp(t *testing.T, s *Store, c *clock, name string) (seed string, recovery []string) {
	t.Helper()
	setup, _, err := s.NewSetupCode("")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := account.HashPassword(firstPassword)
	if err != nil {
		t.Fatal(err)
	}
	if seed, err = account.NewSeed(); err != nil {
		t.Fatal(err)
	}
	recovery, a, err := s.FinishSetup(setup, name, hash, seed, step(c.at))
	if err != nil || a.Name != name || a.Revision != 1 || a.RecoveryLeft != 10 || len(recovery) != 10 {
		t.Fatalf("setup: %+v, %d codes: %v", a, len(recovery), err)
	}
	return seed, recovery
}

func TestASetupCodeMakesTheFirstAccountOnce(t *testing.T) {
	s, _, c, _ := newStore(t)
	if exists, err := s.Exists(); err != nil || exists {
		t.Fatalf("a new vault has an account: %v %v", exists, err)
	}
	setup, until, err := s.NewSetupCode("")
	if err != nil || !until.Equal(c.at.Add(SetupLife)) {
		t.Fatalf("setup code until %v: %v", until, err)
	}
	if err := s.CheckSetup(setup, "ada"); err != nil {
		t.Fatalf("the setup code was refused: %v", err)
	}
	if err := s.CheckSetup("aaaaaa-bbbbbb-cccccc-dddddd", "ada"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a wrong setup code: %v", err)
	}
	hash, _ := account.HashPassword(firstPassword)
	seed, _ := account.NewSeed()
	if _, _, err := s.FinishSetup("aaaaaa-bbbbbb-cccccc-dddddd", "ada", hash, seed, step(c.at)); !errors.Is(err, ErrRefused) {
		t.Fatalf("setup finished with a wrong code: %v", err)
	}
	if _, a, err := s.FinishSetup(setup, "ada", hash, seed, step(c.at)); err != nil || a.Revision != 1 {
		t.Fatalf("setup: %+v %v", a, err)
	}
	if exists, err := s.Exists(); err != nil || !exists {
		t.Fatalf("the account is missing: %v %v", exists, err)
	}
	if err := s.CheckSetup(setup, "ada"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a spent setup code still works: %v", err)
	}
	if _, _, err := s.FinishSetup(setup, "bob", hash, seed, step(c.at)); !errors.Is(err, ErrRefused) {
		t.Fatalf("a spent setup code made a second account: %v", err)
	}
	if _, _, err := s.NewSetupCode(""); !errors.Is(err, ErrRefused) {
		t.Fatalf("a second first account was offered: %v", err)
	}
	if _, _, err := s.NewSetupCode("bob"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a setup code for an unknown account: %v", err)
	}
}

func TestASetupCodeStopsWorkingAfterADay(t *testing.T) {
	s, _, c, _ := newStore(t)
	setup, _, err := s.NewSetupCode("")
	if err != nil {
		t.Fatal(err)
	}
	c.at = c.at.Add(SetupLife)
	if err := s.CheckSetup(setup, "ada"); !errors.Is(err, ErrRefused) {
		t.Fatalf("an expired setup code: %v", err)
	}
	// A new code replaces the old one.
	again, _, err := s.NewSetupCode("")
	if err != nil || s.CheckSetup(again, "ada") != nil || s.CheckSetup(setup, "ada") == nil {
		t.Fatalf("a new setup code: %v", err)
	}
}

func TestSignInTakesThePasswordThenOneCodeOnce(t *testing.T) {
	s, _, c, _ := newStore(t)
	seed, recovery := setUp(t, s, c, "ada")
	if _, err := s.CheckPassword("ada", "not the password at all"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a wrong password: %v", err)
	}
	if _, err := s.CheckPassword("bob", firstPassword); !errors.Is(err, ErrRefused) {
		t.Fatalf("an unknown name: %v", err)
	}
	a, err := s.CheckPassword("ada", firstPassword)
	if err != nil || a.Revision != 1 {
		t.Fatalf("the password: %+v %v", a, err)
	}
	// The code that confirmed the phone at setup is spent already.
	if _, err := s.UseCode("ada", 1, code(t, seed, c.at)); !errors.Is(err, ErrRefused) {
		t.Fatalf("the setup code's step was accepted again: %v", err)
	}
	c.at = c.at.Add(30 * time.Second)
	now := code(t, seed, c.at)
	if _, err := s.UseCode("ada", 1, now); err != nil {
		t.Fatalf("a fresh phone code: %v", err)
	}
	if _, err := s.UseCode("ada", 1, now); !errors.Is(err, ErrRefused) {
		t.Fatalf("a phone code was accepted twice: %v", err)
	}
	c.at = c.at.Add(2 * time.Minute)
	if _, err := s.UseCode("ada", 1, code(t, seed, c.at.Add(-2*time.Minute))); !errors.Is(err, ErrRefused) {
		t.Fatalf("an old phone code: %v", err)
	}
	if _, err := s.UseCode("ada", 1, "12345a"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a malformed code: %v", err)
	}
	a, err = s.UseCode("ada", 1, recovery[3])
	if err != nil || a.RecoveryLeft != 9 {
		t.Fatalf("a recovery code: %+v %v", a, err)
	}
	if _, err := s.UseCode("ada", 1, recovery[3]); !errors.Is(err, ErrRefused) {
		t.Fatalf("a recovery code was accepted twice: %v", err)
	}
	if _, err := s.UseCode("ada", 2, recovery[4]); !errors.Is(err, ErrChanged) {
		t.Fatalf("a code for an account changed since the password: %v", err)
	}
}

func TestASetupCodeForAnAccountReplacesItsSignIn(t *testing.T) {
	s, _, c, _ := newStore(t)
	oldSeed, oldRecovery := setUp(t, s, c, "ada")
	setup, _, err := s.NewSetupCode("ada")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSetup(setup, "bob"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a reset code for another name: %v", err)
	}
	hash, _ := account.HashPassword(nextPassword)
	seed, _ := account.NewSeed()
	c.at = c.at.Add(time.Minute)
	recovery, a, err := s.FinishSetup(setup, "ada", hash, seed, step(c.at))
	if err != nil || a.Revision != 2 || len(recovery) != 10 {
		t.Fatalf("reset: %+v %v", a, err)
	}
	if _, err := s.CheckPassword("ada", firstPassword); !errors.Is(err, ErrRefused) {
		t.Fatalf("the old password still works: %v", err)
	}
	if _, err := s.CheckPassword("ada", nextPassword); err != nil {
		t.Fatalf("the new password: %v", err)
	}
	c.at = c.at.Add(30 * time.Second)
	if _, err := s.UseCode("ada", 2, code(t, oldSeed, c.at)); !errors.Is(err, ErrRefused) {
		t.Fatalf("the old phone still works: %v", err)
	}
	if _, err := s.UseCode("ada", 2, oldRecovery[0]); !errors.Is(err, ErrRefused) {
		t.Fatalf("an old recovery code still works: %v", err)
	}
	if _, err := s.UseCode("ada", 2, code(t, seed, c.at)); err != nil {
		t.Fatalf("the new phone: %v", err)
	}
}

func TestPasswordPhoneAndRecoveryChangesCountARevision(t *testing.T) {
	s, _, c, _ := newStore(t)
	seed, recovery := setUp(t, s, c, "ada")
	if _, err := s.ChangePassword("ada", 1, "not the password at all", nextPassword); !errors.Is(err, ErrRefused) {
		t.Fatalf("a wrong current password: %v", err)
	}
	for _, weak := range []string{"short", firstPassword, "abcdabcdabcdabcdabcd"} {
		if _, err := s.ChangePassword("ada", 1, firstPassword, weak); !errors.Is(err, ErrWeak) {
			t.Fatalf("new password %q: %v", weak, err)
		}
	}
	if _, err := s.ChangePassword("ada", 2, firstPassword, nextPassword); !errors.Is(err, ErrChanged) {
		t.Fatalf("a change against a later revision: %v", err)
	}
	a, err := s.ChangePassword("ada", 1, firstPassword, nextPassword)
	if err != nil || a.Revision != 2 {
		t.Fatalf("password change: %+v %v", a, err)
	}
	if _, err := s.CheckPassword("ada", firstPassword); !errors.Is(err, ErrRefused) {
		t.Fatalf("the old password still works: %v", err)
	}
	next, _ := account.NewSeed()
	c.at = c.at.Add(30 * time.Second)
	if _, err := s.ReplacePhone("ada", 1, next, step(c.at)); !errors.Is(err, ErrChanged) {
		t.Fatalf("a phone change against an older revision: %v", err)
	}
	if a, err = s.ReplacePhone("ada", 2, next, step(c.at)); err != nil || a.Revision != 3 {
		t.Fatalf("phone change: %+v %v", a, err)
	}
	c.at = c.at.Add(30 * time.Second)
	if _, err := s.UseCode("ada", 3, code(t, seed, c.at)); !errors.Is(err, ErrRefused) {
		t.Fatalf("the old phone still works: %v", err)
	}
	if _, err := s.UseCode("ada", 3, code(t, next, c.at)); err != nil {
		t.Fatalf("the new phone: %v", err)
	}
	fresh, a, err := s.NewRecoveryCodes("ada", 3)
	if err != nil || a.Revision != 4 || a.RecoveryLeft != 10 || len(fresh) != 10 {
		t.Fatalf("new recovery codes: %+v %v", a, err)
	}
	if _, err := s.UseCode("ada", 4, recovery[0]); !errors.Is(err, ErrRefused) {
		t.Fatalf("an old recovery code still works: %v", err)
	}
	if _, err := s.UseCode("ada", 4, fresh[9]); err != nil {
		t.Fatalf("a new recovery code: %v", err)
	}
}

func TestTheAccountIsSealedAndReadStrictly(t *testing.T) {
	s, v, c, dir := newStore(t)
	seed, recovery := setUp(t, s, c, "operator-ada")
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "rootwell.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"operator-ada", seed, recovery[0], firstPassword} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("the vault file holds %q in the clear", secret)
		}
	}
	key := v.CodeKey()
	other, _, _, _ := newStore(t)
	if bytes.Equal(key, other.v.CodeKey()) {
		t.Fatal("two vaults share a code key")
	}
}

func TestAnAccountRecordWithAnUnknownFieldIsRefused(t *testing.T) {
	s, v, c, _ := newStore(t)
	setUp(t, s, c, "ada")
	if err := v.Update(func(tx *vault.Tx) error {
		plain, _, err := tx.Get(kindAccount, s.accountID("ada"))
		if err != nil {
			return err
		}
		changed := append(bytes.TrimSuffix(plain, []byte("}")), []byte(`,"role":"owner"}`)...)
		return tx.Put(kindAccount, s.accountID("ada"), changed)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckPassword("ada", firstPassword); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a record with an unknown field was read: %v", err)
	}
}

func TestNamesAreComparedWithoutCase(t *testing.T) {
	for typed, want := range map[string]string{"Ada": "ada", "OPS.team-1": "ops.team-1"} {
		if got, ok := Name(typed); !ok || got != want {
			t.Fatalf("Name(%q) = %q, %v", typed, got, ok)
		}
	}
	for _, bad := range []string{"", ".ada", "ada lovelace", "ада"} {
		if _, ok := Name(bad); ok {
			t.Fatalf("Name(%q) was accepted", bad)
		}
	}
}
