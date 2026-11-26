// Package pfxkeyexport extracts one authenticated, matching private key from
// the bounded offline PFX profile and returns only encrypted PKCS#8 PEM.
// It exports no plaintext or trust verdict and performs no storage/network I/O.
package pfxkeyexport

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/pfxinspect"
	"github.com/youmark/pkcs8"
)

var (
	ErrInvalid        = errors.New("PFX key export failed")
	ErrExportPassword = errors.New("output password does not meet policy")
)

const outputIterations = 600_000

// Export accepts one immutable PFX snapshot, its current password (empty for
// a PFX saved without one), the exact inspected leaf fingerprint, and a fresh
// output password. It uses explicit PBES2/PBKDF2-HMAC-SHA-256/AES-256-CBC
// parameters, never the dependency's weaker defaults. The caller must clear
// the encrypted output after saving it; Go cannot guarantee erasure of
// internal key copies. A refusal wraps the pfxinspect error that caused it.
func Export(input []byte, pfxPassword, fingerprint string, outputPassword []byte) ([]byte, error) {
	if !validOutputPassword(outputPassword) || !pfxinspect.ValidFingerprint(fingerprint) {
		return nil, ErrExportPassword
	}
	if len(input) == 0 || len(input) > 1<<20 {
		return nil, ErrInvalid
	}
	// Keep inspection and extraction tied to the same bytes even if another
	// caller were to reuse or change its source buffer while we work.
	bound := bytes.Clone(input)
	defer clear(bound)
	var output []byte
	// The key comes from the same authenticated decode that matched it to the
	// selected certificate, whatever the bag order in the file.
	err := pfxinspect.Open(bound, pfxPassword, func(result pfxinspect.Result, key crypto.Signer) error {
		if result.MatchingCertificate.SHA256Fingerprint != fingerprint {
			return ErrInvalid
		}
		selected, ok := result.CertificateDER(fingerprint)
		if !ok {
			return ErrInvalid
		}
		defer clear(selected)
		leaf, err := x509.ParseCertificate(selected)
		if err != nil {
			return ErrInvalid
		}
		expected, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			return ErrInvalid
		}
		actual, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil || len(actual) != len(expected) || subtle.ConstantTimeCompare(actual, expected) != 1 {
			return ErrInvalid
		}
		options := &pkcs8.Opts{
			Cipher: pkcs8.AES256CBC,
			KDFOpts: pkcs8.PBKDF2Opts{
				SaltSize: 16, IterationCount: outputIterations, HMACHash: crypto.SHA256,
			},
		}
		der, err := pkcs8.MarshalPrivateKey(key, outputPassword, options)
		if err != nil || len(der) == 0 || len(der) > 64<<10 {
			clear(der)
			return ErrInvalid
		}
		defer clear(der)
		// The decoder sees only Rootwell-generated encrypted output, not a
		// caller-supplied key file with unbounded KDF parameters.
		verified, err := pkcs8.ParsePKCS8PrivateKey(der, outputPassword)
		if err != nil {
			return ErrInvalid
		}
		defer keymatch.ClearParsedKey(verified)
		verifiedSigner, ok := verified.(crypto.Signer)
		if !ok {
			return ErrInvalid
		}
		verifiedSPKI, err := x509.MarshalPKIXPublicKey(verifiedSigner.Public())
		if err != nil || len(verifiedSPKI) != len(expected) || subtle.ConstantTimeCompare(verifiedSPKI, expected) != 1 {
			return ErrInvalid
		}
		output = pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
		if len(output) == 0 {
			return ErrInvalid
		}
		return nil
	})
	if err != nil {
		clear(output)
		if errors.Is(err, ErrInvalid) {
			return nil, ErrInvalid
		}
		return nil, errors.Join(ErrInvalid, err)
	}
	return output, nil
}

func validOutputPassword(value []byte) bool {
	if len(value) < 20 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
