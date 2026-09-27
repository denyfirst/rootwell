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
	"encoding/hex"
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
	labelV1    = "rootwell.instance-access.v1"
	labelV2    = "rootwell.instance-access.v2"
	setup      = "change-required"
	ready      = "ready"
)

var (
	ErrWrongPassword     = errors.New("installation password is incorrect")
	ErrChangeRequired    = errors.New("initial password must be changed")
	ErrWeakPassword      = errors.New("password must contain at least 15 characters")
	ErrPasswordTooLong   = errors.New("password must not exceed 1024 bytes")
	ErrPasswordUnchanged = errors.New("new password must differ from current password")
	ErrInvalidAccess     = errors.New("installation access file is invalid")
	ErrIdentityMissing   = errors.New("installation identity is not enrolled")
	ErrIdentityExists    = errors.New("installation identity is already enrolled")
)

type envelope struct {
	Version        int    `json:"version"`
	State          string `json:"state"`
	KDF            string `json:"kdf"`
	Rounds         int    `json:"rounds"`
	Salt           []byte `json:"salt"`
	Nonce          []byte `json:"nonce"`
	Key            []byte `json:"key"`
	InstallationID []byte `json:"installation_id,omitempty"`
}

// IdentityUpgradeCandidate is an encrypted v2 replacement prepared from an
// authenticated v1 snapshot. It is not installed by this package. A future
// writer must check ExpectedRevision under exclusive single-writer control
// before any replacement, then verify the result and backup pairing.
type IdentityUpgradeCandidate struct {
	ExpectedRevision [32]byte
	EncryptedAccess  []byte
	InstallationID   []byte
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
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return errors.New("installation identity could not be generated")
	}
	body, err := seal(key, initialPassword, setup, id)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return errors.New("installation directory could not be opened")
	}
	defer root.Close()
	name := filepath.Base(path)
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("installation access file could not be created")
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = root.Remove(name)
		return errors.New("installation access file could not be written")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = root.Remove(name)
		return errors.New("installation access file could not be written")
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(name)
		return errors.New("installation access file could not be closed")
	}
	return nil
}

// Open returns the data key only after the initial password has been changed.
// The caller owns the returned key and must never log or serialize it.
func Open(path, password string) ([]byte, error) {
	key, state, _, err := unseal(path, password)
	if err != nil {
		return nil, err
	}
	if state != ready {
		clear(key)
		return nil, ErrChangeRequired
	}
	return key, nil
}

// OpenWithIdentity releases the data key and authenticated installation ID
// only for ready v2 installations. Older v1 installations require an explicit
// future enrollment ceremony before durable inventory can use them.
func OpenWithIdentity(path, password string) ([]byte, []byte, error) {
	key, state, id, err := unseal(path, password)
	if err != nil {
		return nil, nil, err
	}
	if state != ready {
		clear(key)
		return nil, nil, ErrChangeRequired
	}
	if len(id) != 16 {
		clear(key)
		return nil, nil, ErrIdentityMissing
	}
	return key, id, nil
}

// Authenticate checks a password without releasing the data key. The boolean
// is true only when the installation still requires its first password change.
func Authenticate(path, password string) (bool, error) {
	key, state, _, err := unseal(path, password)
	if err != nil {
		return false, err
	}
	clear(key)
	return state == setup, nil
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

// PrepareIdentityUpgrade authenticates a ready legacy v1 access file and
// prepares a v2 envelope with the same data key and password. It never writes
// a file, enables recovery, or changes a running installation. The candidate
// must not be installed until a separately reviewed locked writer exists.
func PrepareIdentityUpgrade(path, password string) (IdentityUpgradeCandidate, error) {
	if len(password) == 0 || len(password) > maxPass {
		return IdentityUpgradeCandidate{}, ErrWrongPassword
	}
	body, err := readAccess(path)
	if err != nil {
		return IdentityUpgradeCandidate{}, err
	}
	key, state, id, err := unsealBody(body, password)
	if err != nil {
		return IdentityUpgradeCandidate{}, err
	}
	defer clear(key)
	if state != ready {
		return IdentityUpgradeCandidate{}, ErrChangeRequired
	}
	if len(id) != 0 {
		return IdentityUpgradeCandidate{}, ErrIdentityExists
	}
	newID := make([]byte, 16)
	if _, err := rand.Read(newID); err != nil {
		return IdentityUpgradeCandidate{}, errors.New("installation identity could not be generated")
	}
	upgraded, err := seal(key, password, ready, newID)
	if err != nil {
		return IdentityUpgradeCandidate{}, err
	}
	return IdentityUpgradeCandidate{
		ExpectedRevision: sha256.Sum256(body),
		EncryptedAccess:  upgraded,
		InstallationID:   newID,
	}, nil
}

func change(path, current, next, requiredState string) error {
	if err := checkPassword(next); err != nil {
		return err
	}
	if current == next {
		return ErrPasswordUnchanged
	}
	key, state, id, err := unseal(path, current)
	if err != nil {
		return err
	}
	defer clear(key)
	if state != requiredState {
		return errors.New("installation password state does not allow this change")
	}
	body, err := seal(key, next, ready, id)
	if err != nil {
		return err
	}
	return replace(path, body)
}

func checkPassword(password string) error {
	if len(password) > maxPass {
		return ErrPasswordTooLong
	}
	if len([]rune(password)) < 15 {
		return ErrWeakPassword
	}
	return nil
}

func seal(key []byte, password, state string, id []byte) ([]byte, error) {
	if len(key) != 32 || (len(id) != 0 && len(id) != 16) || (state != setup && state != ready) {
		return nil, ErrInvalidAccess
	}
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
	if len(id) == 16 {
		e.Version = 2
		e.InstallationID = append([]byte(nil), id...)
	}
	e.Key = gcm.Seal(nil, nonce, key, accessAAD(e))
	return json.Marshal(e)
}

func accessAAD(e envelope) []byte {
	if e.Version == 1 {
		return []byte(labelV1 + ":" + e.State)
	}
	aad := []byte(labelV2 + ":" + e.State + ":")
	return append(aad, e.InstallationID...)
}

func unseal(path, password string) ([]byte, string, []byte, error) {
	if len(password) == 0 || len(password) > maxPass {
		return nil, "", nil, ErrWrongPassword
	}
	body, err := readAccess(path)
	if err != nil {
		return nil, "", nil, err
	}
	return unsealBody(body, password)
}

func unsealBody(body []byte, password string) ([]byte, string, []byte, error) {
	if len(password) == 0 || len(password) > maxPass {
		return nil, "", nil, ErrWrongPassword
	}
	if len(body) > maxFile {
		return nil, "", nil, ErrInvalidAccess
	}
	var e envelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&e) != nil || decoder.Decode(new(any)) != io.EOF ||
		!((e.Version == 1 && len(e.InstallationID) == 0) || (e.Version == 2 && len(e.InstallationID) == 16)) ||
		(e.State != setup && e.State != ready) || e.KDF != "pbkdf2-sha256" ||
		e.Rounds != iterations || len(e.Salt) != 16 || len(e.Nonce) != 12 || len(e.Key) != 48 {
		return nil, "", nil, ErrInvalidAccess
	}
	derived, err := pbkdf2.Key(sha256.New, password, e.Salt, e.Rounds, 32)
	if err != nil {
		return nil, "", nil, ErrInvalidAccess
	}
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, "", nil, ErrInvalidAccess
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", nil, ErrInvalidAccess
	}
	key, err := gcm.Open(nil, e.Nonce, e.Key, accessAAD(e))
	if err != nil || len(key) != 32 {
		return nil, "", nil, ErrWrongPassword
	}
	return key, e.State, append([]byte(nil), e.InstallationID...), nil
}

// Revision identifies the exact encrypted access-file contents observed by a
// session. It does not authenticate an installation or release its data key.
func Revision(path string) ([32]byte, error) {
	body, err := readAccess(path)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(body), nil
}

func readAccess(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, ErrInvalidAccess
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, ErrInvalidAccess
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, ErrInvalidAccess
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) ||
		(runtime.GOOS != "windows" && opened.Mode().Perm()&0o077 != 0) {
		return nil, ErrInvalidAccess
	}
	body, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil || len(body) > maxFile {
		return nil, ErrInvalidAccess
	}
	return body, nil
}

func replace(path string, body []byte) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return ErrInvalidAccess
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return ErrInvalidAccess
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return errors.New("new password could not be saved")
	}
	tempName := ".rootwell-access-" + hex.EncodeToString(random)
	f, err := root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("new password could not be saved")
	}
	defer root.Remove(tempName)
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
	if err := root.Rename(tempName, name); err != nil {
		return errors.New("new password could not be saved")
	}
	return nil
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
