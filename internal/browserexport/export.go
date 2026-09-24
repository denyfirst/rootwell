// Package browserexport prepares one public certificate for a browser-managed
// download. It never handles private-key material or writes to a filesystem.
package browserexport

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"strings"

	"github.com/denyfirst/rootwell/internal/limits"
	"github.com/denyfirst/rootwell/internal/publicbundle"
)

const SchemaVersion = "rootwell.browser.export.v1"

type ErrorCode string

const (
	ErrorInvalidRequest ErrorCode = "invalid-browser-request"
	ErrorTooLarge       ErrorCode = "input-too-large"
	ErrorInvalidSource  ErrorCode = "invalid-public-source"
	ErrorNotFound       ErrorCode = "certificate-not-found"
	ErrorInternal       ErrorCode = "internal-failure"
)

type Result struct {
	Encoding    string
	Fingerprint string
	Filename    string
	Bytes       []byte
}

// Prepare re-parses a strict public collection and selects by the full
// fingerprint presented during exploration, never by order or file name.
// Caller must clear Result.Bytes after transferring them to the browser.
func Prepare(input []byte, fingerprint, encoding string) (Result, ErrorCode) {
	if encoding != "pem" && encoding != "der" || !validFingerprint(fingerprint) {
		return Result{}, ErrorInvalidRequest
	}
	entries, err := publicbundle.Parse(input)
	if err != nil {
		if err == publicbundle.ErrTooLarge {
			return Result{}, ErrorTooLarge
		}
		return Result{}, ErrorInvalidSource
	}
	defer func() {
		for _, entry := range entries {
			clear(entry.DER)
		}
	}()
	for _, entry := range entries {
		if entry.Inspection.SHA256Fingerprint != fingerprint {
			continue
		}
		var output []byte
		if encoding == "pem" {
			output = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: entry.DER})
		} else {
			output = bytes.Clone(entry.DER)
		}
		if len(output) == 0 || int64(len(output)) > limits.MaxInputBytes {
			clear(output)
			return Result{}, ErrorInternal
		}
		if !sameCertificate(output, entry.DER, fingerprint) {
			clear(output)
			return Result{}, ErrorInternal
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			clear(output)
			return Result{}, ErrorInternal
		}
		digest := strings.ReplaceAll(fingerprint, ":", "")
		filename := "rootwell-public-" + strings.ToLower(digest[:16]) + "-" + hex.EncodeToString(nonce[:]) + "." + encoding
		return Result{Encoding: encoding, Fingerprint: fingerprint, Filename: filename, Bytes: output}, ""
	}
	return Result{}, ErrorNotFound
}

func sameCertificate(output, original []byte, fingerprint string) bool {
	parsed, err := publicbundle.Parse(output)
	if err != nil || len(parsed) != 1 {
		return false
	}
	defer clear(parsed[0].DER)
	return bytes.Equal(parsed[0].DER, original) && parsed[0].Inspection.SHA256Fingerprint == fingerprint
}

func validFingerprint(value string) bool {
	if len(value) != 95 {
		return false
	}
	for i, character := range value {
		if i%3 == 2 {
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
