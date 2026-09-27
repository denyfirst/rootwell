package instanceaccess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
)

const (
	recoveryMagic = "RWRC1"
	recoveryAAD   = "rootwell.offline-recovery.v1:"
	recoverySize  = len(recoveryMagic) + 16 + 32 + 28 // header, ID, key, GCM nonce/tag
)

var (
	ErrInvalidRecoveryInput = errors.New("invalid recovery wrap input")
	ErrInvalidRecovery      = errors.New("recovery wrap or code is invalid")
)

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// CreateRecoveryWrap makes a standalone in-memory wrap of the existing data
// key. The caller must obtain the key and ID through an authenticated, ready
// v2 installation and must never log the returned code. Neither result is
// persisted here. The wrap and the access file must later be backed up as a
// verified pair; this function does not implement enrollment or recovery.
func CreateRecoveryWrap(installationID, dataKey []byte) ([]byte, string, error) {
	if len(installationID) != 16 || len(dataKey) != 32 {
		return nil, "", ErrInvalidRecoveryInput
	}
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return nil, "", errors.New("recovery code could not be generated")
	}
	defer clear(codeBytes)
	block, err := aes.NewCipher(codeBytes)
	if err != nil {
		return nil, "", ErrInvalidRecoveryInput
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, "", ErrInvalidRecoveryInput
	}
	code := encodeRecoveryCode(codeBytes)
	wrap := make([]byte, 0, recoverySize)
	wrap = append(wrap, recoveryMagic...)
	wrap = append(wrap, installationID...)
	// #nosec G407 -- NewGCMWithRandomNonce requires nil and generates its own nonce.
	wrap = gcm.Seal(wrap, nil, dataKey, recoveryContext(installationID))
	return wrap, code, nil
}

// OpenRecoveryWrap recovers only the wrapped data key after authenticating
// the caller's expected installation ID. Every invalid code, wrap, or ID
// mismatch has the same error and releases no partial key.
func OpenRecoveryWrap(wrap []byte, code string, expectedInstallationID []byte) ([]byte, error) {
	if len(expectedInstallationID) != 16 {
		return nil, ErrInvalidRecoveryInput
	}
	if len(wrap) != recoverySize || !bytes.Equal(wrap[:len(recoveryMagic)], []byte(recoveryMagic)) ||
		!bytes.Equal(wrap[len(recoveryMagic):len(recoveryMagic)+16], expectedInstallationID) {
		return nil, ErrInvalidRecovery
	}
	codeBytes, err := decodeRecoveryCode(code)
	if err != nil {
		return nil, ErrInvalidRecovery
	}
	defer clear(codeBytes)
	block, err := aes.NewCipher(codeBytes)
	if err != nil {
		return nil, ErrInvalidRecovery
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, ErrInvalidRecovery
	}
	key, err := gcm.Open(nil, nil, wrap[len(recoveryMagic)+16:], recoveryContext(expectedInstallationID))
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, ErrInvalidRecovery
	}
	return key, nil
}

func recoveryContext(id []byte) []byte {
	aad := []byte(recoveryAAD)
	return append(aad, id...)
}

func encodeRecoveryCode(raw []byte) string {
	encoded := strings.ToLower(recoveryEncoding.EncodeToString(raw))
	var parts []string
	for len(encoded) > 0 {
		n := min(4, len(encoded))
		parts = append(parts, encoded[:n])
		encoded = encoded[n:]
	}
	return strings.Join(parts, "-")
}

func decodeRecoveryCode(code string) ([]byte, error) {
	if len(code) != 64 { // 52 base32 symbols and twelve separators
		return nil, ErrInvalidRecovery
	}
	compact := strings.ReplaceAll(code, "-", "")
	raw, err := recoveryEncoding.DecodeString(strings.ToUpper(compact))
	if err != nil || len(raw) != 32 || encodeRecoveryCode(raw) != code {
		clear(raw)
		return nil, ErrInvalidRecovery
	}
	return raw, nil
}
