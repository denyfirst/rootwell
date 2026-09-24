// Package publicbundle reads one public X.509 certificate or a strict PEM
// certificate bundle. It never interprets a certificate as a trust anchor.
package publicbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"errors"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/limits"
)

var (
	ErrEmpty                = errors.New("public certificate input is empty")
	ErrTooLarge             = errors.New("public certificate input exceeds size limit")
	ErrTooManyCertificates  = errors.New("public certificate bundle exceeds count limit")
	ErrUnexpectedContent    = errors.New("public certificate bundle contains unexpected content")
	ErrInvalidCertificate   = errors.New("public certificate bundle contains an invalid certificate")
	ErrDuplicateCertificate = errors.New("public certificate bundle contains a duplicate certificate")
	ErrMetadataLimit        = errors.New("public certificate metadata exceeds limit")
)

// Entry is a parsed public certificate. DER is a private copy of the public
// certificate bytes for a future separately reviewed export path. Inspection
// is metadata only and does not express a chain, hostname, or trust verdict.
type Entry struct {
	Inspection certinspect.Result
	DER        []byte
}

// Parse accepts exactly one DER X.509 certificate or 1..64 adjacent,
// header-free PEM CERTIFICATE blocks. Total input is bounded to 16 MiB.
// Unknown blocks, prefixes, trailing content, and duplicates fail closed.
func Parse(input []byte) ([]Entry, error) {
	if int64(len(input)) > limits.MaxInputBytes {
		return nil, ErrTooLarge
	}
	if len(bytes.TrimSpace(input)) == 0 {
		return nil, ErrEmpty
	}

	remaining := bytes.TrimSpace(input)
	if !bytes.HasPrefix(remaining, []byte("-----BEGIN ")) {
		entry, err := inspectDER(input, certinspect.EncodingDER)
		if err != nil {
			return nil, err
		}
		return []Entry{entry}, nil
	}

	entries := make([]Entry, 0, 1)
	seen := make(map[[sha256.Size]byte]struct{})
	summaryTextBytes := 0
	for len(remaining) != 0 {
		if len(entries) == limits.MaxCertificatesPerBundle {
			return nil, ErrTooManyCertificates
		}
		// pem.Decode skips arbitrary leading text. Do not allow that behavior to
		// silently turn a mixed or secret-bearing file into a public bundle.
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrUnexpectedContent
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrUnexpectedContent
		}
		entry, err := inspectDER(block.Bytes, certinspect.EncodingPEM)
		if err != nil {
			return nil, err
		}
		summaryTextBytes += len(entry.Inspection.Subject) + len(entry.Inspection.Issuer)
		if summaryTextBytes > limits.MaxMetadataTextBytes {
			return nil, ErrMetadataLimit
		}
		digest := sha256.Sum256(entry.DER)
		if _, exists := seen[digest]; exists {
			return nil, ErrDuplicateCertificate
		}
		seen[digest] = struct{}{}
		entries = append(entries, entry)
		remaining = bytes.TrimSpace(rest)
	}
	return entries, nil
}

func inspectDER(input []byte, encoding certinspect.Encoding) (Entry, error) {
	result, err := certinspect.Inspect(input)
	if err != nil {
		if errors.Is(err, certinspect.ErrResourceLimit) {
			return Entry{}, ErrMetadataLimit
		}
		return Entry{}, ErrInvalidCertificate
	}
	result.Encoding = encoding
	return Entry{Inspection: result, DER: bytes.Clone(input)}, nil
}
