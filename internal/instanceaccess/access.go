// Package instanceaccess holds the local installation's data key behind a
// password. It does not implement HTTP authentication or a vault.
package instanceaccess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	iterations = 600_000
	maxFile    = 4096
	maxPass    = 1024
	label      = "rootwell.instance-access.v1"
	setup      = "change-required"
	ready      = "ready"
)

var (
	ErrWrongPassword  = errors.New("installation password is incorrect")
	ErrChangeRequired = errors.New("initial password must be changed")
	ErrWeakPassword   = errors.New("password must contain at least 15 characters")
	ErrInvalidAccess  = errors.New("installation access file is invalid")
)

type envelope struct {
	Version int    `json:"version"`
	State   string `json:"state"`
	KDF     string `json:"kdf"`
	Rounds  int    `json:"rounds"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Key     []byte `json:"key"`
}

// GenerateInitialPassword creates a per-installation, 160-bit random secret.
// Callers must show it only on an interactive local terminal, never in logs.
func GenerateInitialPassword() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("initial password could not be generated")
	}
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	var parts []string
	for len(encoded) > 0 {
		n := min(5, len(encoded))
		parts = append(parts, encoded[:n])
		encoded = encoded[n:]
	}
	return strings.Join(parts, "-"), nil
}

// Create creates a new access file. It never replaces an existing installation.
// The caller must use a private directory controlled by the local operator.
func Create(path, initialPassword string) error {
	if err := checkPassword(initialPassword); err != nil {
		return err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return errors.New("installation key could not be generated")
	}
	defer clear(key)
	body, err := seal(key, initialPassword, setup)
	if err != nil {
		return err
	}
	// #nosec G304 -- path is a local operator configuration, never an HTTP input.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("installation access file could not be created")
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return errors.New("installation access file could not be written")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return errors.New("installation access file could not be written")
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("installation access file could not be closed")
	}
	return nil
}

// Open returns the data key only after the initial password has been changed.
// The caller owns the returned key and must never log or serialize it.
func Open(path, password string) ([]byte, error) {
	key, state, err := unseal(path, password)
	if err != nil {
		return nil, err
	}
	if state != ready {
		clear(key)
		return nil, ErrChangeRequired
	}
	return key, nil
}

// ChangeInitialPassword is the only operation accepted with the initial
// password. It rewraps the same data key and ends setup mode atomically.
func ChangeInitialPassword(path, initialPassword, nextPassword string) error {
	return change(path, initialPassword, nextPassword, setup)
}

// ChangePassword rewraps an already activated installation's data key.
func ChangePassword(path, currentPassword, nextPassword string) error {
	return change(path, currentPassword, nextPassword, ready)
}

func change(path, current, next, requiredState string) error {
	if err := checkPassword(next); err != nil {
		return err
	}
	if current == next {
		return errors.New("new password must differ from current password")
	}
	key, state, err := unseal(path, current)
	if err != nil {
		return err
	}
	defer clear(key)
	if state != requiredState {
		return errors.New("installation password state does not allow this change")
	}
	body, err := seal(key, next, ready)
	if err != nil {
		return err
	}
	return replace(path, body)
}

func checkPassword(password string) error {
	if len(password) > maxPass {
		return errors.New("password is too long")
	}
	if len([]rune(password)) < 15 {
		return ErrWeakPassword
	}
	return nil
}

func seal(key []byte, password, state string) ([]byte, error) {
	salt, nonce := make([]byte, 16), make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.New("access salt could not be generated")
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("access nonce could not be generated")
	}
	derived, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return nil, errors.New("access key could not be derived")
	}
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, errors.New("access cipher could not be created")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("access cipher could not be created")
	}
	e := envelope{Version: 1, State: state, KDF: "pbkdf2-sha256", Rounds: iterations, Salt: salt, Nonce: nonce}
	e.Key = gcm.Seal(nil, nonce, key, []byte(label+":"+state))
	return json.Marshal(e)
}

func unseal(path, password string) ([]byte, string, error) {
	if len(password) == 0 || len(password) > maxPass {
		return nil, "", ErrWrongPassword
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, "", ErrInvalidAccess
	}
	// #nosec G304 -- path is a local operator configuration, never an HTTP input.
	f, err := os.Open(path)
	if err != nil {
		return nil, "", ErrInvalidAccess
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil || len(body) > maxFile {
		return nil, "", ErrInvalidAccess
	}
	var e envelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&e) != nil || decoder.Decode(new(any)) != io.EOF || e.Version != 1 ||
		(e.State != setup && e.State != ready) || e.KDF != "pbkdf2-sha256" ||
		e.Rounds != iterations || len(e.Salt) != 16 || len(e.Nonce) != 12 || len(e.Key) != 48 {
		return nil, "", ErrInvalidAccess
	}
	derived, err := pbkdf2.Key(sha256.New, password, e.Salt, e.Rounds, 32)
	if err != nil {
		return nil, "", ErrInvalidAccess
	}
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, "", ErrInvalidAccess
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", ErrInvalidAccess
	}
	key, err := gcm.Open(nil, e.Nonce, e.Key, []byte(label+":"+e.State))
	if err != nil || len(key) != 32 {
		return nil, "", ErrWrongPassword
	}
	return key, e.State, nil
}

func replace(path string, body []byte) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ErrInvalidAccess
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".rootwell-access-*")
	if err != nil {
		return errors.New("new password could not be saved")
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return errors.New("new password could not be saved")
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return errors.New("new password could not be saved")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return errors.New("new password could not be saved")
	}
	if err := f.Close(); err != nil {
		return errors.New("new password could not be saved")
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return errors.New("new password could not be saved")
	}
	return nil
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
