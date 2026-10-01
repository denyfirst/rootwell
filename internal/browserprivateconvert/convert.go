// Package browserprivateconvert converts explicitly selected local private
// keys without sending them to the instance inventory or a network service.
package browserprivateconvert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/limits"
	"github.com/youmark/pkcs8"
)

const SchemaVersion = "rootwell.browser.private-convert.v1"

var (
	ErrInvalid               = errors.New("private key cannot be converted")
	ErrPassword              = errors.New("output password does not meet policy")
	ErrInputPasswordRequired = errors.New("encrypted private key requires its current password")
)

// Summary contains no private key, raw key bytes, or input filename.
type Summary struct {
	InputFormat       string `json:"input_format"`
	Algorithm         string `json:"algorithm"`
	Bits              int    `json:"bits"`
	Curve             string `json:"curve"`
	PublicFingerprint string `json:"public_fingerprint"`
}

// Inspect accepts strict unencrypted inputs. InspectWithPassword additionally
// accepts the bounded encrypted PKCS#8 profile of ADR 0035. Neither assesses
// certificate trust or key strength.
func Inspect(input []byte) (Summary, error) {
	return InspectWithPassword(input, nil)
}

func InspectWithPassword(input, password []byte) (Summary, error) {
	var result Summary
	err := withInputKey(input, password, func(key any, encoding keymatch.Encoding) error {
		var err error
		result, err = summarize(key, encoding)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrInputPasswordRequired) {
			return Summary{}, ErrInputPasswordRequired
		}
		return Summary{}, ErrInvalid
	}
	return result, nil
}

// ExportEncrypted reparses one immutable source, binds it to the exact public
// fingerprint shown by Inspect, and emits only password-encrypted PKCS#8 PEM.
// The caller must clear the returned bytes after requesting a download.
func ExportEncrypted(input []byte, expected string, password []byte) ([]byte, string, error) {
	return Export(input, expected, nil, "encrypted-pkcs8-pem", password)
}

// Export binds output to the public fingerprint shown by Inspect. Plaintext
// output is deliberately opt-in at the UI boundary; callers must not choose
// it by default. Browser downloads have no filesystem permission guarantee.
func Export(input []byte, expected string, inputPassword []byte, format string, outputPassword []byte) ([]byte, string, error) {
	encrypted := format == "encrypted-pkcs8-pem"
	if !encrypted && format != "pkcs8-pem" && format != "pkcs8-der" && format != "pkcs1-pem" && format != "pkcs1-der" && format != "sec1-pem" && format != "sec1-der" {
		return nil, "", ErrInvalid
	}
	if (encrypted && !validPassword(outputPassword)) || (!encrypted && len(outputPassword) != 0) {
		return nil, "", ErrPassword
	}
	if encrypted && len(inputPassword) == len(outputPassword) && len(inputPassword) != 0 && subtle.ConstantTimeCompare(inputPassword, outputPassword) == 1 {
		return nil, "", ErrPassword
	}
	if !validFingerprint(expected) || len(input) == 0 || int64(len(input)) > limits.MaxPrivateKeyBytes {
		return nil, "", ErrInvalid
	}
	var output []byte
	err := withInputKey(input, inputPassword, func(key any, encoding keymatch.Encoding) error {
		metadata, err := summarize(key, encoding)
		if err != nil || len(metadata.PublicFingerprint) != len(expected) ||
			subtle.ConstantTimeCompare([]byte(metadata.PublicFingerprint), []byte(expected)) != 1 {
			return ErrInvalid
		}
		if !encrypted {
			var der []byte
			switch format {
			case "pkcs8-pem", "pkcs8-der":
				der, err = x509.MarshalPKCS8PrivateKey(key)
			case "pkcs1-pem", "pkcs1-der":
				value, ok := key.(*rsa.PrivateKey)
				if !ok {
					return ErrInvalid
				}
				der = x509.MarshalPKCS1PrivateKey(value)
			case "sec1-pem", "sec1-der":
				value, ok := key.(*ecdsa.PrivateKey)
				if !ok {
					return ErrInvalid
				}
				der, err = x509.MarshalECPrivateKey(value)
			}
			if err != nil || len(der) == 0 || len(der) > 64<<10 {
				clear(der)
				return ErrInvalid
			}
			defer clear(der)
			if strings.HasSuffix(format, "-der") {
				output = append([]byte(nil), der...)
			} else {
				label := "PRIVATE KEY"
				if strings.HasPrefix(format, "pkcs1-") {
					label = "RSA PRIVATE KEY"
				}
				if strings.HasPrefix(format, "sec1-") {
					label = "EC PRIVATE KEY"
				}
				output = pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der})
			}
			return verifyOutput(output, metadata.PublicFingerprint)
		}
		options := &pkcs8.Opts{
			Cipher: pkcs8.AES256CBC,
			KDFOpts: pkcs8.PBKDF2Opts{
				SaltSize: 16, IterationCount: 600_000, HMACHash: crypto.SHA256,
			},
		}
		der, err := pkcs8.MarshalPrivateKey(key, outputPassword, options)
		if err != nil || len(der) == 0 || len(der) > 64<<10 {
			clear(der)
			return ErrInvalid
		}
		defer clear(der)
		// This decoder reads only the bounded output generated by the fixed
		// options above, never an attacker-supplied encrypted input.
		checked, err := pkcs8.ParsePKCS8PrivateKey(der, outputPassword)
		if err != nil {
			return ErrInvalid
		}
		defer keymatch.ClearParsedKey(checked)
		verified, err := summarize(checked, keymatch.EncodingPKCS8DER)
		if err != nil || verified.PublicFingerprint != metadata.PublicFingerprint {
			return ErrInvalid
		}
		output = pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
		if len(output) == 0 || len(output) > 96<<10 {
			clear(output)
			output = nil
			return ErrInvalid
		}
		return nil
	})
	if err != nil {
		clear(output)
		if errors.Is(err, ErrInputPasswordRequired) {
			return nil, "", ErrInputPasswordRequired
		}
		return nil, "", ErrInvalid
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		clear(output)
		return nil, "", ErrInvalid
	}
	fragment := strings.ToLower(strings.ReplaceAll(expected, ":", "")[:16])
	name := "rootwell-plaintext-key-"
	if encrypted {
		name = "rootwell-encrypted-key-"
	}
	extension := ".pem"
	if strings.HasSuffix(format, "-der") {
		extension = ".der"
	}
	return output, name + fragment + "-" + hex.EncodeToString(nonce[:]) + extension, nil
}

func verifyOutput(output []byte, expected string) error {
	if len(output) == 0 || len(output) > 96<<10 {
		return ErrInvalid
	}
	result, err := Inspect(output)
	if err != nil || result.PublicFingerprint != expected {
		return ErrInvalid
	}
	return nil
}

func summarize(key any, encoding keymatch.Encoding) (Summary, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return Summary{}, ErrInvalid
	}
	public := signer.Public()
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return Summary{}, ErrInvalid
	}
	defer clear(spki)
	digest := sha256.Sum256(spki)
	parts := make([]string, len(digest))
	for i, octet := range digest {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{octet}))
	}
	result := Summary{InputFormat: string(encoding), PublicFingerprint: strings.Join(parts, ":")}
	switch value := public.(type) {
	case *rsa.PublicKey:
		result.Algorithm, result.Bits = "RSA", value.N.BitLen()
	case *ecdsa.PublicKey:
		result.Algorithm, result.Bits, result.Curve = "ECDSA", value.Curve.Params().BitSize, value.Curve.Params().Name
	case ed25519.PublicKey:
		result.Algorithm, result.Bits = "Ed25519", len(value)*8
	default:
		return Summary{}, ErrInvalid
	}
	return result, nil
}

func validPassword(value []byte) bool {
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

func validFingerprint(value string) bool {
	if len(value) != 95 {
		return false
	}
	for index, character := range value {
		if index%3 == 2 {
			if character != ':' {
				return false
			}
		} else if character < '0' || character > '9' && (character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}
