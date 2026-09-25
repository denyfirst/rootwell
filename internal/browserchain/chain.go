// Package browserchain finds possible issuer relationships in a bounded
// public certificate collection. It never selects a trust anchor or verifies
// a TLS server identity.
package browserchain

import (
	"bytes"
	"crypto/x509"
	"encoding/json"

	"github.com/denyfirst/rootwell/internal/limits"
	"github.com/denyfirst/rootwell/internal/publicbundle"
)

const SchemaVersion = "rootwell.browser.chain.v1"
const maxFiles = 8
const maxResponseBytes = 64 << 10
const maxSignatureChecks = 256

type Certificate struct {
	SHA256     string `json:"sha256"`
	Parents    []int  `json:"parents"`
	SelfSigned bool   `json:"self_signed"`
}

type Result struct {
	Verification string        `json:"verification"`
	TrustAnchor  string        `json:"trust_anchor"`
	Certificates []Certificate `json:"certificates"`
}

type Response struct {
	SchemaVersion string  `json:"schema_version"`
	OK            bool    `json:"ok"`
	Result        *Result `json:"result"`
	Error         string  `json:"error"`
}

// Process analyzes one to eight separate public files. Certificate positions
// match the existing Explore ordering. The caller must clear its input copies.
func Process(inputs [][]byte) string {
	if len(inputs) == 0 || len(inputs) > maxFiles {
		return failure("invalid-browser-request")
	}
	totalBytes := int64(0)
	var parsed []*x509.Certificate
	var fingerprints []string
	var rawCopies [][]byte
	defer func() {
		for _, raw := range rawCopies {
			clear(raw)
		}
	}()
	seen := make(map[string]struct{})
	metadataBytes := 0
	for _, input := range inputs {
		if len(input) == 0 || int64(len(input)) > limits.MaxInputBytes-totalBytes {
			return failure("invalid-public-collection")
		}
		totalBytes += int64(len(input))
		entries, err := publicbundle.Parse(input)
		if err != nil {
			return failure("invalid-public-collection")
		}
		for _, entry := range entries {
			rawCopies = append(rawCopies, entry.DER)
			if len(parsed) == limits.MaxCertificatesPerBundle {
				return failure("invalid-public-collection")
			}
			fingerprint := entry.Inspection.SHA256Fingerprint
			if _, exists := seen[fingerprint]; exists {
				return failure("invalid-public-collection")
			}
			seen[fingerprint] = struct{}{}
			metadataBytes += len(entry.Inspection.Subject) + len(entry.Inspection.Issuer)
			if metadataBytes > limits.MaxMetadataTextBytes {
				return failure("invalid-public-collection")
			}
			certificate, parseError := x509.ParseCertificate(entry.DER)
			if parseError != nil {
				return failure("invalid-public-collection")
			}
			parsed = append(parsed, certificate)
			fingerprints = append(fingerprints, fingerprint)
		}
	}
	result := Result{Verification: "not-performed", TrustAnchor: "not-selected"}
	signatureChecks := 0
	for childIndex, child := range parsed {
		item := Certificate{SHA256: fingerprints[childIndex], Parents: []int{}}
		for parentIndex, parent := range parsed {
			if !parent.BasicConstraintsValid || !parent.IsCA || !bytes.Equal(child.RawIssuer, parent.RawSubject) {
				continue
			}
			signatureChecks++
			if signatureChecks > maxSignatureChecks {
				return failure("invalid-public-collection")
			}
			if err := child.CheckSignatureFrom(parent); err != nil {
				continue
			}
			if childIndex == parentIndex {
				item.SelfSigned = true
			} else {
				item.Parents = append(item.Parents, parentIndex)
			}
		}
		result.Certificates = append(result.Certificates, item)
	}
	encoded, err := json.Marshal(Response{SchemaVersion: SchemaVersion, OK: true, Result: &result})
	if err != nil || len(encoded) > maxResponseBytes {
		return failure("internal-failure")
	}
	return string(encoded)
}

// FailureResponse covers rejected bridge arguments without reflecting input.
func FailureResponse(code string) string {
	if code != "invalid-browser-request" && code != "invalid-public-collection" && code != "internal-failure" {
		code = "internal-failure"
	}
	return failure(code)
}

func failure(code string) string {
	encoded, _ := json.Marshal(Response{SchemaVersion: SchemaVersion, Error: code})
	return string(encoded)
}
