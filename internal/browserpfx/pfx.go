// Package browserpfx exposes the bounded offline PFX profile to a one-shot
// browser worker. It returns no private material except for an explicit,
// newly encrypted key export.
package browserpfx

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/denyfirst/rootwell/internal/certinspect"
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

type Summary struct {
	Certificates []Certificate `json:"certificates"`
}

func Inspect(input, password []byte) (Summary, error) {
	if len(input) == 0 || len(input) > 1<<20 || len(password) == 0 || len(password) > 128 {
		return Summary{}, ErrInvalid
	}
	result, err := pfxinspect.Inspect(input, string(password))
	if err != nil {
		return Summary{}, ErrInvalid
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
		return nil, "", ErrInvalid
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
		return nil, "", ErrInvalid
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
	output, err := pfxcreate.Create(certificate, key, issuers, string(password))
	if err != nil {
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
