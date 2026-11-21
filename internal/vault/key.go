// Package vault keeps Rootwell's secrets the way Keybash keeps its own: one
// instance key in its own file, apart from the database and its backups; a
// bbolt database in a private directory; and every record sealed under its
// own random key, which is wrapped under a key derived from the instance key
// and bound to the record's kind, ID and revision (ADR 0088).
package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// KeySize is the instance key's length in bytes.
const KeySize = 32

// ErrRefused hides why a vault operation failed: a wrong key, a damaged file
// and a refused input all read the same to a caller outside the package.
var ErrRefused = errors.New("vault refused the request")

// NewInstanceKey returns 32 random bytes from the operating system.
func NewInstanceKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, ErrRefused
	}
	return key, nil
}

// WriteKeyFile creates the instance key file. It never replaces a file, and
// the directory must be private to the service (see privateDirectory).
func WriteKeyFile(path string, key []byte) error {
	if len(key) != KeySize || privateDirectory(filepath.Dir(path), "") != nil {
		return ErrRefused
	}
	// #nosec G304 -- the path is the operator's own key file location, never request input.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrRefused
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return ErrRefused
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return ErrRefused
	}
	if err := f.Close(); err != nil {
		return ErrRefused
	}
	return syncDirectory(filepath.Dir(path))
}

// ReadKeyFile reads exactly 32 bytes from a private regular file.
func ReadKeyFile(path string) ([]byte, error) {
	if privateKeyFile(path) != nil {
		return nil, ErrRefused
	}
	// #nosec G304 -- the path is the operator's own key file location, never request input.
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrRefused
	}
	defer f.Close()
	key := make([]byte, KeySize+1)
	n, err := io.ReadFull(f, key)
	if n != KeySize || !errors.Is(err, io.ErrUnexpectedEOF) {
		clear(key)
		return nil, ErrRefused
	}
	return key[:KeySize], nil
}

// The instance key's recovery code: "RW1-" and the key with a four-byte check,
// in base32, grouped by five. It is written down once, apart from the server
// and its backups. With a backup it restores everything; without it no backup
// can be opened.
const recoveryPrefix = "RW1"

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func recoveryCheck(key []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("rootwell/instance-key-code/v1/"))
	_, _ = h.Write(key)
	return h.Sum(nil)[:4]
}

// RecoveryCode prints the instance key for writing down.
func RecoveryCode(key []byte) (string, error) {
	if len(key) != KeySize {
		return "", ErrRefused
	}
	raw := append(bytes.Clone(key), recoveryCheck(key)...)
	defer clear(raw)
	text := recoveryEncoding.EncodeToString(raw)
	var code strings.Builder
	code.WriteString(recoveryPrefix)
	for i := 0; i < len(text); i += 5 {
		code.WriteByte('-')
		code.WriteString(text[i:min(i+5, len(text))])
	}
	return code.String(), nil
}

// ParseRecoveryCode accepts the code as printed, in either case and with or
// without its separators, and refuses any other text or a failed check.
func ParseRecoveryCode(code string) ([]byte, error) {
	if len(code) > 256 {
		return nil, ErrRefused
	}
	compact := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	text, found := strings.CutPrefix(compact, recoveryPrefix)
	if !found || len(text) != 58 {
		return nil, ErrRefused
	}
	raw, err := recoveryEncoding.DecodeString(text)
	if err != nil || len(raw) != KeySize+4 || recoveryEncoding.EncodeToString(raw) != text ||
		subtle.ConstantTimeCompare(recoveryCheck(raw[:KeySize]), raw[KeySize:]) != 1 {
		clear(raw)
		return nil, ErrRefused
	}
	key := bytes.Clone(raw[:KeySize])
	clear(raw)
	return key, nil
}
