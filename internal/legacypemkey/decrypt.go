// Package legacypemkey opens the old OpenSSL encrypted PEM key format:
//
//	-----BEGIN RSA PRIVATE KEY-----
//	Proc-Type: 4,ENCRYPTED
//	DEK-Info: AES-256-CBC,<hex IV>
//
// Rootwell reads this format so such a key can be used, and never writes it.
// It derives the cipher key with OpenSSL's EVP_BytesToKey (MD5, one round),
// the documented scheme of the format, not a scheme of Rootwell's own.
package legacypemkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- reads 3DES-protected keys that older OpenSSL wrote; never used to protect output.
	"crypto/md5" // #nosec G501 -- EVP_BytesToKey of this read-only legacy format is defined over MD5.
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

type cipherSpec struct {
	keyBytes, blockBytes int
	block                func([]byte) (cipher.Block, error)
}

var ciphers = map[string]cipherSpec{
	"DES-EDE3-CBC": {24, 8, des.NewTripleDESCipher},
	"AES-128-CBC":  {16, 16, aes.NewCipher},
	"AES-192-CBC":  {24, 16, aes.NewCipher},
	"AES-256-CBC":  {32, 16, aes.NewCipher},
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
	spec, known := ciphers[name]
	if !ok || !known || len(ivHex) != 2*spec.blockBytes {
		return nil, ErrUnsupported
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil || len(block.Bytes)%spec.blockBytes != 0 {
		return nil, ErrUnsupported
	}
	if len(password) == 0 || len(password) > maxPasswordBytes {
		return nil, ErrWrongPassword
	}
	key := bytesToKey(password, iv[:8], spec.keyBytes)
	defer clear(key)
	engine, err := spec.block(key) // #nosec G401 -- decrypts a read-only legacy key format.
	if err != nil {
		return nil, ErrUnsupported
	}
	plain := make([]byte, len(block.Bytes))
	cipher.NewCBCDecrypter(engine, iv).CryptBlocks(plain, block.Bytes)
	last := plain[len(plain)-1]
	padding := int(last)
	if padding == 0 || padding > spec.blockBytes {
		clear(plain)
		return nil, ErrWrongPassword
	}
	var differs byte
	for _, value := range plain[len(plain)-padding:] {
		differs |= value ^ last
	}
	if differs != 0 {
		clear(plain)
		return nil, ErrWrongPassword
	}
	der := plain[:len(plain)-padding]
	// With a wrong password the padding is still right about once in 256
	// tries; the key structure is the real check.
	var parsed any
	var parseErr error
	if block.Type == "RSA PRIVATE KEY" {
		parsed, parseErr = x509.ParsePKCS1PrivateKey(der)
	} else {
		parsed, parseErr = x509.ParseECPrivateKey(der)
	}
	if parseErr == nil {
		keymatch.ClearParsedKey(parsed)
	} else {
		clear(plain)
		return nil, ErrWrongPassword
	}
	return der, nil
}

// bytesToKey is OpenSSL's EVP_BytesToKey with MD5 and one round, as the
// legacy PEM format defines: D_i = MD5(D_(i-1) || password || salt).
func bytesToKey(password, salt []byte, size int) []byte {
	var key, previous []byte
	for len(key) < size {
		h := md5.New() // #nosec G401 -- the legacy PEM format's own key derivation.
		h.Write(previous)
		h.Write(password)
		h.Write(salt)
		clear(previous)
		previous = h.Sum(nil)
		key = append(key, previous...)
	}
	clear(previous)
	clear(key[size:])
	return key[:size]
}
