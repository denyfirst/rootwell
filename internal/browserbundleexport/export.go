// Package browserbundleexport prepares an explicitly selected public PEM
// certificate collection for a browser-managed download. It never builds a
// trusted chain, handles private keys, or writes to disk.
package browserbundleexport

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"

	"github.com/denyfirst/rootwell/internal/limits"
	"github.com/denyfirst/rootwell/internal/publicbundle"
)

const SchemaVersion = "rootwell.browser.bundle-export.v1"

type ErrorCode string

const (
	ErrorInvalidRequest ErrorCode = "invalid-browser-request"
	ErrorInvalidSource  ErrorCode = "invalid-public-source"
	ErrorChangedSource  ErrorCode = "changed-public-source"
	ErrorTooLarge       ErrorCode = "input-too-large"
	ErrorInternal       ErrorCode = "internal-failure"
)

type Result struct {
	Fingerprints []string
	Filename     string
	Bytes        []byte
}

// Prepare requires the full ordered Explore fingerprint snapshot as well as
// an explicitly selected, order-preserving subset. No inferred chain order or
// trust decision can enter the exported bytes. Caller clears Result.Bytes.
func Prepare(inputs [][]byte, expected, selected []string) (Result, ErrorCode) {
	if len(inputs) < 1 || len(inputs) > 8 || len(expected) < 1 || len(expected) > limits.MaxCertificatesPerBundle ||
		len(selected) < 1 || len(selected) > len(expected) {
		return Result{}, ErrorInvalidRequest
	}
	for _, fingerprint := range expected {
		if !validFingerprint(fingerprint) {
			return Result{}, ErrorInvalidRequest
		}
	}
	for _, fingerprint := range selected {
		if !validFingerprint(fingerprint) {
			return Result{}, ErrorInvalidRequest
		}
	}
	remaining := int(limits.MaxInputBytes)
	var entries []publicbundle.Entry
	defer func() {
		for _, entry := range entries {
			clear(entry.DER)
		}
	}()
	seen := make(map[string]struct{})
	metadataBytes := 0
	for _, input := range inputs {
		if len(input) == 0 || len(input) > remaining {
			return Result{}, ErrorTooLarge
		}
		remaining -= len(input)
		parsed, err := publicbundle.Parse(input)
		if err != nil {
			return Result{}, ErrorInvalidSource
		}
		for _, entry := range parsed {
			entries = append(entries, entry)
			if len(entries) > limits.MaxCertificatesPerBundle {
				return Result{}, ErrorTooLarge
			}
			fingerprint := entry.Inspection.SHA256Fingerprint
			if _, duplicate := seen[fingerprint]; duplicate {
				return Result{}, ErrorInvalidSource
			}
			seen[fingerprint] = struct{}{}
			metadataBytes += len(entry.Inspection.Subject) + len(entry.Inspection.Issuer)
			if metadataBytes > limits.MaxMetadataTextBytes {
				return Result{}, ErrorTooLarge
			}
		}
	}
	if len(entries) != len(expected) {
		return Result{}, ErrorChangedSource
	}
	for index, entry := range entries {
		if entry.Inspection.SHA256Fingerprint != expected[index] {
			return Result{}, ErrorChangedSource
		}
	}
	var output []byte
	var selectedDER [][]byte
	defer func() {
		if output != nil {
			clear(output)
		}
	}()
	selectedIndex := 0
	for _, entry := range entries {
		if selectedIndex == len(selected) || entry.Inspection.SHA256Fingerprint != selected[selectedIndex] {
			continue
		}
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: entry.DER})
		if len(block) == 0 || len(block) > int(limits.MaxInputBytes)-len(output) {
			clear(block)
			return Result{}, ErrorTooLarge
		}
		output = append(output, block...)
		clear(block)
		selectedDER = append(selectedDER, entry.DER)
		selectedIndex++
	}
	if selectedIndex != len(selected) {
		return Result{}, ErrorInvalidRequest
	}
	if !sameCollection(output, selected, selectedDER) {
		return Result{}, ErrorInternal
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Result{}, ErrorInternal
	}
	result := Result{
		Fingerprints: append([]string(nil), selected...),
		Filename:     "rootwell-public-bundle-" + hex.EncodeToString(nonce[:]) + ".pem",
		Bytes:        output,
	}
	output = nil
	return result, ""
}

func sameCollection(output []byte, selected []string, originals [][]byte) bool {
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
		if entry.Inspection.SHA256Fingerprint != selected[index] || !bytes.Equal(entry.DER, originals[index]) {
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
			continue
		}
		if character < '0' || character > '9' {
			if character < 'A' || character > 'F' {
				return false
			}
		}
	}
	return true
}
