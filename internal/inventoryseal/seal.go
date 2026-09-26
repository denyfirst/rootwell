// Package inventoryseal authenticates and encrypts a bounded public-inventory
// record in memory. It does not read or write storage, validate record payloads,
// manage installation identities, or provide recovery.
package inventoryseal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const (
	maxPlaintext = 128 << 10
	magic        = "RWINV001"
	aadLabel     = "rootwell.public-inventory.record.v1"
	keySize      = 32
	sealOverhead = 28 // 96-bit random nonce plus 128-bit GCM tag.
)

var (
	ErrKey     = errors.New("inventory encryption key is invalid")
	ErrContext = errors.New("inventory record context is invalid")
	ErrSize    = errors.New("inventory record exceeds size limit")
	ErrRecord  = errors.New("encrypted inventory record is invalid")
)

// Context is supplied by a future trusted storage layer, not by a browser.
// InstallationID identifies one installation, RecordID one certificate, and
// Generation the expected revision. A persisted monotonic generation source is
// still needed before this codec can defend against rollback.
type Context struct {
	InstallationID [16]byte
	RecordID       [32]byte
	Generation     uint64
}

// Seal returns a versioned AES-256-GCM record with a fresh random nonce from
// the Go standard library. The plaintext may contain sensitive public-cert
// metadata but must already have passed application-level validation.
func Seal(key []byte, context Context, plaintext []byte) ([]byte, error) {
	if len(key) != keySize {
		return nil, ErrKey
	}
	if !validContext(context) {
		return nil, ErrContext
	}
	if len(plaintext) == 0 || len(plaintext) > maxPlaintext {
		return nil, ErrSize
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, ErrKey
	}
	out := make([]byte, 0, len(magic)+len(plaintext)+sealOverhead)
	out = append(out, magic...)
	// #nosec G407 -- NewGCMWithRandomNonce requires a nil nonce; it generates
	// a fresh random nonce and prepends it to the ciphertext.
	return aead.Seal(out, nil, plaintext, associatedData(context)), nil
}

// Open authenticates a record against the exact expected installation,
// certificate identity, and generation. It never returns partial plaintext.
func Open(key []byte, context Context, record []byte) ([]byte, error) {
	if len(key) != keySize {
		return nil, ErrKey
	}
	if !validContext(context) {
		return nil, ErrContext
	}
	if len(record) < len(magic)+sealOverhead+1 ||
		len(record) > len(magic)+sealOverhead+maxPlaintext ||
		!bytes.Equal(record[:len(magic)], []byte(magic)) {
		return nil, ErrRecord
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, ErrKey
	}
	plaintext, err := aead.Open(nil, nil, record[len(magic):], associatedData(context))
	if err != nil || len(plaintext) == 0 || len(plaintext) > maxPlaintext {
		return nil, ErrRecord
	}
	return plaintext, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func validContext(context Context) bool {
	return context.InstallationID != [16]byte{} && context.RecordID != [32]byte{} && context.Generation > 0
}

func associatedData(context Context) []byte {
	data := make([]byte, 0, len(aadLabel)+16+32+8)
	data = append(data, aadLabel...)
	data = append(data, context.InstallationID[:]...)
	data = append(data, context.RecordID[:]...)
	var generation [8]byte
	binary.BigEndian.PutUint64(generation[:], context.Generation)
	return append(data, generation[:]...)
}
