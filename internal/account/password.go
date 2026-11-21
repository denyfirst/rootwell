// Package account holds the sign-in pieces Rootwell shares with Keybash
// (ADR 0088): Argon2id passwords checked against a common-password list,
// RFC 6238 phone codes that are never accepted twice, one-time recovery codes
// and the bootstrap code that creates the first account. It stores nothing;
// the vault keeps what it returns.
package account

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// ErrRefused hides why an input was refused.
var ErrRefused = errors.New("account request refused")

// MaxPasswordBytes is the one length limit for a password, everywhere: setting
// it, signing in and any later check use the same bound (audit RW-09).
const MaxPasswordBytes = 1024

// MinPasswordRunes is the shortest password accepted when one is set.
const MinPasswordRunes = 15

// PasswordHash is Argon2id with fixed parameters. A stored hash cannot carry
// caller-chosen work or memory, so a crafted record cannot exhaust the host.
type PasswordHash struct {
	Version int    `json:"version"`
	Salt    []byte `json:"salt"`
	Sum     []byte `json:"sum"`
}

// Format keeps a hash out of logs and error text.
func (PasswordHash) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("[password hash]")) }

func passwordInput(password string) bool {
	return len(password) > 0 && len(password) <= MaxPasswordBytes && utf8.ValidString(password)
}

// CheckNewPassword applies the rules for a password being set: at least 15
// characters, at most 1024 bytes, valid UTF-8, and not a common password or a
// short pattern repeated.
func CheckNewPassword(password string) error {
	if !passwordInput(password) || utf8.RuneCountInString(password) < MinPasswordRunes || blockedPassword(password) {
		return ErrRefused
	}
	return nil
}

// HashPassword is Argon2id with 64 MiB, three passes, four lanes, a random
// 128-bit salt and a 256-bit sum, as in Keybash. The bytes are kept exactly,
// without trimming or normalisation.
func HashPassword(password string) (PasswordHash, error) {
	if err := CheckNewPassword(password); err != nil {
		return PasswordHash{}, err
	}
	h := PasswordHash{Version: 1, Salt: make([]byte, 16)}
	if _, err := rand.Read(h.Salt); err != nil {
		return PasswordHash{}, ErrRefused
	}
	h.Sum = passwordKey(password, h.Salt)
	return h, nil
}

func passwordKey(password string, salt []byte) []byte {
	value := []byte(password)
	defer clear(value) // best effort; the runtime may keep other copies
	return argon2.IDKey(value, salt, 3, 64*1024, 4, 32)
}

// Verify compares in constant time. A malformed hash or input never matches.
func (h PasswordHash) Verify(password string) bool {
	if h.Version != 1 || len(h.Salt) != 16 || len(h.Sum) != 32 || !passwordInput(password) {
		return false
	}
	key := passwordKey(password, h.Salt)
	defer clear(key)
	return subtle.ConstantTimeCompare(key, h.Sum) == 1
}

// The SecLists 10k list Keybash pins (docs/DEPENDENCIES.md), byte for byte;
// no password is ever looked up online.
//
//go:embed password-blocklist.txt
var commonPasswords string

var blockedPasswords = func() map[string]bool {
	m := make(map[string]bool)
	for _, s := range strings.Split(commonPasswords, "\n") {
		if s = strings.TrimSpace(s); s != "" {
			m[strings.ToLower(s)] = true
		}
	}
	for _, s := range []string{"correcthorsebatterystaple", "passwordpassword", "rootwellrootwellrootwell",
		"thisisapassword", "letmeinletmeinletmein", "12345678901234567890"} {
		m[s] = true
	}
	return m
}()

func blockedPassword(value string) bool {
	if blockedPasswords[strings.ToLower(strings.TrimSpace(value))] {
		return true
	}
	runes := []rune(value)
	// A run that only counts up or down, such as abcdefghijklmnop, or digits
	// that wrap round, such as 1234567890123456.
	if len(runes) > 2 {
		step := countStep(runes[0], runes[1])
		sequence := step != 0
		for i := 2; sequence && i < len(runes); i++ {
			sequence = countStep(runes[i-1], runes[i]) == step
		}
		if sequence {
			return true
		}
	}
	for period := 1; period <= 4 && period < len(runes); period++ {
		repeated := true
		for i := period; i < len(runes); i++ {
			if runes[i] != runes[i%period] {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}
	return false
}

// countStep is 1 when b follows a, -1 when b comes before it, and 0 otherwise;
// digits wrap from 9 to 0.
func countStep(a, b rune) int {
	if a >= '0' && a <= '9' && b >= '0' && b <= '9' {
		switch (b - a + 10) % 10 {
		case 1:
			return 1
		case 9:
			return -1
		}
		return 0
	}
	switch b - a {
	case 1:
		return 1
	case -1:
		return -1
	}
	return 0
}
