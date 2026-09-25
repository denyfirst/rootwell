// Package browserverifiedexport prepares a public server chain only after
// re-running offline verification against independently supplied trust.
package browserverifiedexport

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"time"

	"github.com/denyfirst/rootwell/internal/browserverify"
	"github.com/denyfirst/rootwell/internal/limits"
	"github.com/denyfirst/rootwell/internal/publicbundle"
)

const SchemaVersion = "rootwell.browser.verified-export.v1"
const maxOutputBytes = 4 << 20

type ErrorCode string

const (
	ErrorInvalidRequest ErrorCode = "invalid-browser-request"
	ErrorNotVerified    ErrorCode = "not-verified"
	ErrorChangedVerdict ErrorCode = "changed-verification"
	ErrorInvalidSource  ErrorCode = "invalid-public-source"
	ErrorTooLarge       ErrorCode = "input-too-large"
	ErrorInternal       ErrorCode = "internal-failure"
)

type Result struct {
	Fingerprints []string
	Hostname     string
	EvaluatedAt  string
	Filename     string
	Bytes        []byte
}

// PrepareSimple re-verifies current public files. expected is the entire
// ordered chain shown at the preceding Verify step, including the trust root.
// The output omits that root and includes no private key. Caller clears Bytes.
func PrepareSimple(sources [][]byte, trust []byte, hostname string, now time.Time, expected []string) (Result, ErrorCode) {
	if !validExpected(expected) {
		return Result{}, ErrorInvalidRequest
	}
	verification := browserverify.Simple(sources, trust, hostname, now)
	return prepare(verification, sources, hostname, now, expected)
}

// PrepareExplicit applies the same rule to explicitly assigned leaf and
// intermediates. A successful prior verdict alone never authorizes export.
func PrepareExplicit(leaf, intermediates, trust []byte, hostname string, now time.Time, expected []string) (Result, ErrorCode) {
	if !validExpected(expected) {
		return Result{}, ErrorInvalidRequest
	}
	verification := browserverify.Explicit(leaf, intermediates, trust, hostname, now)
	sources := [][]byte{leaf}
	if len(intermediates) != 0 {
		sources = append(sources, intermediates)
	}
	return prepare(verification, sources, hostname, now, expected)
}

func prepare(encoded string, sources [][]byte, hostname string, now time.Time, expected []string) (Result, ErrorCode) {
	var verdict browserverify.Response
	if err := json.Unmarshal([]byte(encoded), &verdict); err != nil || verdict.SchemaVersion != browserverify.SchemaVersion {
		return Result{}, ErrorInternal
	}
	if !verdict.OK || verdict.Result == nil {
		if verdict.Error != nil {
			switch verdict.Error.Code {
			case "input-too-large":
				return Result{}, ErrorTooLarge
			case "invalid-public-source":
				return Result{}, ErrorInvalidSource
			}
		}
		return Result{}, ErrorNotVerified
	}
	verified := verdict.Result
	if verdict.Error != nil || verified.Profile != "tls-server" || verified.Verification != "passed" ||
		verified.TrustSource != "explicit-file" || verified.Network != "disabled" ||
		verified.Revocation != "not-checked" || verified.Hostname != hostname ||
		verified.EvaluatedAt != now.UTC().Format(time.RFC3339Nano) ||
		len(verified.Chain) != len(expected) {
		return Result{}, ErrorChangedVerdict
	}
	for index, member := range verified.Chain {
		if member.SHA256Fingerprint != expected[index] {
			return Result{}, ErrorChangedVerdict
		}
	}
	public, code := collectPublicSources(sources)
	if code != "" {
		return Result{}, code
	}
	defer func() {
		for _, raw := range public {
			clear(raw)
		}
	}()
	var output []byte
	defer func() {
		if output != nil {
			clear(output)
		}
	}()
	selected := expected[:len(expected)-1] // the independently supplied trust anchor stays out of the server chain
	for _, fingerprint := range selected {
		der, found := public[fingerprint]
		if !found {
			return Result{}, ErrorChangedVerdict
		}
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if len(block) == 0 || len(block) > maxOutputBytes-len(output) {
			clear(block)
			return Result{}, ErrorTooLarge
		}
		output = append(output, block...)
		clear(block)
	}
	if !sameOutput(output, selected, public) {
		return Result{}, ErrorInternal
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Result{}, ErrorInternal
	}
	result := Result{
		Fingerprints: append([]string(nil), selected...), Hostname: hostname,
		EvaluatedAt: verified.EvaluatedAt,
		Filename:    "rootwell-verified-fullchain-" + hex.EncodeToString(nonce[:]) + ".pem",
		Bytes:       output,
	}
	output = nil
	return result, ""
}

func collectPublicSources(sources [][]byte) (map[string][]byte, ErrorCode) {
	public := make(map[string][]byte)
	cleanup := func() {
		for _, raw := range public {
			clear(raw)
		}
	}
	count := 0
	remaining := int(limits.MaxInputBytes)
	for _, source := range sources {
		if len(source) == 0 || len(source) > remaining {
			cleanup()
			return nil, ErrorTooLarge
		}
		remaining -= len(source)
		entries, err := publicbundle.Parse(source)
		if err != nil {
			cleanup()
			return nil, ErrorInvalidSource
		}
		for index, entry := range entries {
			count++
			if count > limits.MaxCertificatesPerBundle {
				for _, unused := range entries[index:] {
					clear(unused.DER)
				}
				cleanup()
				return nil, ErrorTooLarge
			}
			fingerprint := entry.Inspection.SHA256Fingerprint
			if _, duplicate := public[fingerprint]; duplicate {
				for _, unused := range entries[index:] {
					clear(unused.DER)
				}
				cleanup()
				return nil, ErrorInvalidSource
			}
			public[fingerprint] = entry.DER
		}
	}
	return public, ""
}

func sameOutput(output []byte, selected []string, originals map[string][]byte) bool {
	parsed, err := publicbundle.Parse(output)
	if err != nil {
		return false
	}
	defer func() {
		for _, entry := range parsed {
			clear(entry.DER)
		}
	}()
	if len(parsed) != len(selected) {
		return false
	}
	for index, entry := range parsed {
		if entry.Inspection.SHA256Fingerprint != selected[index] || !bytes.Equal(entry.DER, originals[selected[index]]) {
			return false
		}
	}
	return true
}

func validExpected(expected []string) bool {
	if len(expected) < 2 || len(expected) > limits.MaxCertificatesPerBundle {
		return false
	}
	seen := make(map[string]struct{}, len(expected))
	for _, fingerprint := range expected {
		if len(fingerprint) != 95 {
			return false
		}
		for index, character := range fingerprint {
			if index%3 == 2 {
				if character != ':' {
					return false
				}
			} else if character < '0' || character > '9' {
				if character < 'A' || character > 'F' {
					return false
				}
			}
		}
		if _, duplicate := seen[fingerprint]; duplicate {
			return false
		}
		seen[fingerprint] = struct{}{}
	}
	return true
}
