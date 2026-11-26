// Package legacypemkey opens the old OpenSSL encrypted PEM key format:
//
//	-----BEGIN RSA PRIVATE KEY-----
//	Proc-Type: 4,ENCRYPTED
//	DEK-Info: AES-256-CBC,<hex IV>
//
// Rootwell reads this format so such a key can be used, and never writes it.
// The decryption is the standard library's own reader of the format; this
// package only bounds what reaches it and tells a wrong password apart.
package legacypemkey

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/limits"
)

var (
	// ErrUnsupported is a block this reader does not open: another key type,
	// another cipher, extra headers or damaged framing.
	ErrUnsupported = errors.New("old-style encrypted key is not supported")
	// ErrWrongPassword means the password does not open the key. A damaged
	// ciphertext looks the same and cannot be told apart.
	ErrWrongPassword = errors.New("password does not open the key")
)

const maxPasswordBytes = 256

// The ciphers read, by their block size. Single DES is refused.
var blockBytes = map[string]int{
	"DES-EDE3-CBC": 8,
	"AES-128-CBC":  16,
	"AES-192-CBC":  16,
	"AES-256-CBC":  16,
}

// IsEncrypted reports whether a PEM block uses the old Proc-Type encryption.
func IsEncrypted(block *pem.Block) bool {
	return block != nil && (block.Headers["Proc-Type"] != "" || block.Headers["DEK-Info"] != "")
}

// Decrypt returns the PKCS#1 (RSA) or SEC 1 (EC) DER inside one encrypted
// block. The caller owns and must clear it, and still parses it strictly.
func Decrypt(block *pem.Block, password []byte) ([]byte, error) {
	if block == nil || (block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY") || len(block.Headers) != 2 ||
		block.Headers["Proc-Type"] != "4,ENCRYPTED" || len(block.Bytes) == 0 || int64(len(block.Bytes)) > limits.MaxPrivateKeyBytes {
		return nil, ErrUnsupported
	}
	name, ivHex, ok := strings.Cut(block.Headers["DEK-Info"], ",")
	size, known := blockBytes[name]
	if !ok || !known || len(ivHex) != 2*size || len(block.Bytes)%size != 0 {
		return nil, ErrUnsupported
	}
	if _, err := hex.DecodeString(ivHex); err != nil {
		return nil, ErrUnsupported
	}
	if len(password) == 0 || len(password) > maxPasswordBytes {
		return nil, ErrWrongPassword
	}
	//lint:ignore SA1019 Reads the old format with the standard library's own reader instead of a copy of its key derivation; Rootwell never writes this format, and a person decrypting their own file has no padding oracle to fear.
	der, err := x509.DecryptPEMBlock(block, password)
	switch {
	case errors.Is(err, x509.IncorrectPasswordError):
		return nil, ErrWrongPassword
	case err != nil:
		return nil, ErrUnsupported
	}
	// With a wrong password the padding is still right about once in 256
	// tries; the key structure is the real check.
	var parsed any
	var parseErr error
	if block.Type == "RSA PRIVATE KEY" {
		parsed, parseErr = x509.ParsePKCS1PrivateKey(der)
	} else {
		parsed, parseErr = x509.ParseECPrivateKey(der)
	}
	if parseErr != nil {
		clear(der)
		return nil, ErrWrongPassword
	}
	keymatch.ClearParsedKey(parsed)
	return der, nil
}
