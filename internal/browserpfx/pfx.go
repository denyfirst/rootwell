// Package browserpfx exposes the bounded offline PFX profile to a one-shot
// browser worker. Private output requires an explicit encrypted export or
// separately requested, transient on-screen reveal.
package browserpfx

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/denyfirst/rootwell/internal/browserprivateconvert"
	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/pfxcreate"
	"github.com/denyfirst/rootwell/internal/pfxinspect"
	"github.com/denyfirst/rootwell/internal/pfxkeyexport"
)

const SchemaVersion = "rootwell.browser.pfx.v1"

var ErrInvalid = errors.New("PFX operation failed")

type Certificate struct {
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotAfter    string `json:"not_after"`
	Fingerprint string `json:"fingerprint"`
	IsCA        bool   `json:"is_ca"`
	MatchingKey bool   `json:"matching_key"`
}

// RevealKey reauthenticates the exact selected matching certificate and
// returns strict PKCS#8 PEM for a transient view only. The caller must clear
// the bytes, hide the view promptly, and never download or persist this output.
func RevealKey(input, password []byte, fingerprint string) ([]byte, error) {
	if len(input) == 0 || len(input) > 1<<20 || len(password) > 128 || !pfxinspect.ValidFingerprint(fingerprint) {
		return nil, ErrInvalid
	}
	bound := bytes.Clone(input)
	defer clear(bound)
	var output []byte
	// The key is the one the same authenticated decode matched to the
	// selected certificate, whatever the bag order in the file.
	err := pfxinspect.Open(bound, string(password), func(summary pfxinspect.Result, key crypto.Signer) error {
		if summary.MatchingCertificate.SHA256Fingerprint != fingerprint {
			return ErrInvalid
		}
		expected, ok := summary.CertificateDER(fingerprint)
		if !ok {
			return ErrInvalid
		}
		defer clear(expected)
		plain, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil || len(plain) == 0 || len(plain) > 64<<10 {
			clear(plain)
			return ErrInvalid
		}
		defer clear(plain)
		matched, err := keymatch.Match(expected, plain)
		if err != nil || !matched.Match {
			return ErrInvalid
		}
		output = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: plain})
		if len(output) == 0 || len(output) > 96<<10 {
			return ErrInvalid
		}
		return nil
	})
	if err != nil {
		clear(output)
		return nil, refusal(err)
	}
	return output, nil
}

// refusal keeps ErrInvalid as the error every caller checks and wraps the
// pfxinspect cause, so the page can say whether the password was wrong.
func refusal(err error) error {
	if err == nil || errors.Is(err, ErrInvalid) {
		return ErrInvalid
	}
	return errors.Join(ErrInvalid, err)
}

type Summary struct {
	Certificates []Certificate `json:"certificates"`
}

// Inspect opens a PFX with its password, which is empty for a PFX saved
// without one, and returns public certificate metadata only.
func Inspect(input, password []byte) (Summary, error) {
	if len(input) == 0 || len(input) > 1<<20 || len(password) > 128 {
		return Summary{}, ErrInvalid
	}
	result, err := pfxinspect.Inspect(input, string(password))
	if err != nil {
		return Summary{}, refusal(err)
	}
	certs := make([]Certificate, 0, 1+len(result.Additional))
	certs = append(certs, summarize(result.MatchingCertificate, true))
	for _, additional := range result.Additional {
		certs = append(certs, summarize(additional, false))
	}
	return Summary{Certificates: certs}, nil
}

func summarize(result certinspect.Result, matching bool) Certificate {
	return Certificate{Subject: result.Subject, Issuer: result.Issuer,
		NotAfter:    result.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		Fingerprint: result.SHA256Fingerprint, IsCA: result.IsCA, MatchingKey: matching}
}

// ExportCertificate reauthenticates and rechecks the selected fingerprint.
// It does not assert that an included certificate is trusted or in a chain.
func ExportCertificate(input, password []byte, fingerprint, format string) ([]byte, string, error) {
	if (format != "pem" && format != "der") || !pfxinspect.ValidFingerprint(fingerprint) {
		return nil, "", ErrInvalid
	}
	result, err := pfxinspect.Inspect(input, string(password))
	if err != nil {
		return nil, "", refusal(err)
	}
	der, ok := result.CertificateDER(fingerprint)
	if !ok {
		return nil, "", ErrInvalid
	}
	if format == "der" {
		name := filename("certificate", fingerprint, ".der")
		if name == "" {
			clear(der)
			return nil, "", ErrInvalid
		}
		return der, name, nil
	}
	output := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	clear(der)
	if len(output) == 0 {
		return nil, "", ErrInvalid
	}
	name := filename("certificate", fingerprint, ".pem")
	if name == "" {
		clear(output)
		return nil, "", ErrInvalid
	}
	return output, name, nil
}

func ExportKey(input, password []byte, fingerprint string, outputPassword []byte) ([]byte, string, error) {
	if !pfxinspect.ValidFingerprint(fingerprint) ||
		(len(password) == len(outputPassword) && len(password) != 0 && subtle.ConstantTimeCompare(password, outputPassword) == 1) {
		return nil, "", ErrInvalid
	}
	output, err := pfxkeyexport.Export(input, string(password), fingerprint, outputPassword)
	if err != nil {
		return nil, "", refusal(err)
	}
	name := filename("encrypted-key", fingerprint, ".pem")
	if name == "" {
		clear(output)
		return nil, "", ErrInvalid
	}
	return output, name, nil
}

// Create accepts one certificate, one matching unencrypted key and an
// optional ordered issuer bundle. It deliberately does not claim universal
// vendor compatibility or preserve PFX bag attributes.
func Create(certificate, key, issuers, password []byte) ([]byte, string, error) {
	return CreateWithInputPassword(certificate, key, issuers, password, nil)
}

// CreateWithInputPassword also accepts the bounded encrypted PKCS#8 profile.
// The input password must be empty for plaintext keys. Decryption and match
// happen inside the caller's one-shot worker without an intermediate download.
func CreateWithInputPassword(certificate, key, issuers, password, inputPassword []byte) ([]byte, string, error) {
	return CreateProfile(certificate, key, issuers, password, inputPassword, pfxcreate.Modern)
}

// CreateProfile is CreateWithInputPassword with a chosen protection: the
// modern default, or 3DES for Windows Server 2016 and older.
func CreateProfile(certificate, key, issuers, password, inputPassword []byte, profile pfxcreate.Profile) ([]byte, string, error) {
	if !pfxcreate.PasswordAllowed(string(password)) || len(certificate) == 0 || len(certificate) > 1<<20 || len(issuers) > 1<<20 || len(inputPassword) > 256 ||
		(len(inputPassword) != 0 && len(inputPassword) == len(password) && subtle.ConstantTimeCompare(inputPassword, password) == 1) {
		return nil, "", ErrInvalid
	}
	var output []byte
	err := browserprivateconvert.WithInputKey(key, inputPassword, func(parsed any, _ keymatch.Encoding) error {
		var createErr error
		output, createErr = pfxcreate.CreateWithParsedKeyProfile(certificate, parsed, issuers, string(password), profile)
		return createErr
	})
	if err != nil || len(output) == 0 || len(output) > 1<<20 {
		clear(output)
		return nil, "", ErrInvalid
	}
	name := filename("bundle", "", ".pfx")
	if name == "" {
		clear(output)
		return nil, "", ErrInvalid
	}
	return output, name, nil
}

func filename(kind, fingerprint, extension string) string {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ""
	}
	part := ""
	if len(fingerprint) == 95 {
		part = strings.ToLower(strings.ReplaceAll(fingerprint, ":", "")[:16]) + "-"
	}
	return "rootwell-" + kind + "-" + part + hex.EncodeToString(nonce[:]) + extension
}
