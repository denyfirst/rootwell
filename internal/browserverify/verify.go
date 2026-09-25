// Package browserverify exposes the existing explicit-trust TLS verifier to
// a bounded, public-only browser workflow. It performs no network access.
package browserverify

import (
	"bytes"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/certverify"
	"github.com/denyfirst/rootwell/internal/limits"
	"github.com/denyfirst/rootwell/internal/publicbundle"
)

const SchemaVersion = "rootwell.browser.verify.v1"
const maxResponseBytes = 1 << 20

type Failure struct {
	Code string `json:"code"`
}

type Result struct {
	Profile            string                          `json:"profile"`
	Verification       string                          `json:"verification"`
	Hostname           string                          `json:"hostname"`
	EvaluatedAt        string                          `json:"evaluated_at"`
	TrustSource        string                          `json:"trust_source"`
	RootPin            string                          `json:"root_pin"`
	Revocation         string                          `json:"revocation"`
	Network            string                          `json:"network"`
	IgnoredSourceRoots int                             `json:"ignored_source_roots"`
	Chain              []certverify.CertificateSummary `json:"chain"`
}

type Response struct {
	SchemaVersion string   `json:"schema_version"`
	OK            bool     `json:"ok"`
	Result        *Result  `json:"result"`
	Error         *Failure `json:"error"`
}

// Explicit passes independently selected leaf, optional intermediate bundle,
// and trust bundle directly to the reviewed CLI verifier core.
func Explicit(leaf, intermediates, trust []byte, hostname string, now time.Time) string {
	return ExplicitWithRootPin(leaf, intermediates, trust, hostname, now, "")
}

// ExplicitWithRootPin additionally checks the chosen path's trust anchor
// against a full, independently obtained SHA-256 certificate fingerprint.
func ExplicitWithRootPin(leaf, intermediates, trust []byte, hostname string, now time.Time, rootPin string) string {
	if !withinCombinedLimit(leaf, intermediates, trust) {
		return failure("input-too-large")
	}
	return verify(leaf, intermediates, trust, hostname, now, 0, rootPin)
}

// Simple classifies public source certificates but never obtains trust from
// that collection. Exactly one non-CA leaf candidate is required. Self-signed
// CA certificates in the source are ignored; only the separately supplied
// trust bundle can authenticate the resulting path.
func Simple(sources [][]byte, trust []byte, hostname string, now time.Time) string {
	return SimpleWithRootPin(sources, trust, hostname, now, "")
}

// SimpleWithRootPin never derives the expected fingerprint from source files.
func SimpleWithRootPin(sources [][]byte, trust []byte, hostname string, now time.Time, rootPin string) string {
	if len(sources) < 1 || len(sources) > 8 || len(trust) == 0 {
		return failure("invalid-browser-request")
	}
	inputs := make([][]byte, 0, len(sources)+1)
	inputs = append(inputs, sources...)
	inputs = append(inputs, trust)
	if !withinCombinedLimit(inputs...) {
		return failure("input-too-large")
	}
	var leaf []byte
	var intermediates []byte
	var copies [][]byte
	defer func() {
		for _, raw := range copies {
			clear(raw)
		}
		clear(intermediates)
	}()
	seen := make(map[string]struct{})
	count := 0
	metadataBytes := 0
	ignoredRoots := 0
	for _, source := range sources {
		entries, err := publicbundle.Parse(source)
		if err != nil {
			return failure("invalid-public-source")
		}
		for _, entry := range entries {
			copies = append(copies, entry.DER)
			count++
			if count > limits.MaxCertificatesPerBundle {
				return failure("input-too-large")
			}
			fingerprint := entry.Inspection.SHA256Fingerprint
			if _, duplicate := seen[fingerprint]; duplicate {
				return failure("duplicate-certificate")
			}
			seen[fingerprint] = struct{}{}
			metadataBytes += len(entry.Inspection.Subject) + len(entry.Inspection.Issuer)
			if metadataBytes > limits.MaxMetadataTextBytes {
				return failure("input-too-large")
			}
			certificate, err := x509.ParseCertificate(entry.DER)
			if err != nil {
				return failure("invalid-public-source")
			}
			if !certificate.IsCA {
				if leaf != nil {
					return failure("ambiguous-leaf")
				}
				leaf = entry.DER
				continue
			}
			if !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
				return failure("invalid-public-source")
			}
			if bytes.Equal(certificate.RawIssuer, certificate.RawSubject) && certificate.CheckSignatureFrom(certificate) == nil {
				ignoredRoots++
				continue
			}
			block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: entry.DER})
			if len(block) == 0 || len(block) > int(limits.MaxInputBytes)-len(intermediates) {
				clear(block)
				return failure("input-too-large")
			}
			intermediates = append(intermediates, block...)
			clear(block)
		}
	}
	if leaf == nil {
		return failure("missing-leaf")
	}
	return verify(leaf, intermediates, trust, hostname, now, ignoredRoots, rootPin)
}

func verify(leaf, intermediates, trust []byte, hostname string, now time.Time, ignoredRoots int, rootPin string) string {
	pin, valid := parseRootPin(rootPin)
	if !valid {
		return failure("invalid-root-pin")
	}
	result, err := certverify.Verify(leaf, certverify.Options{
		TrustBundle: trust, IntermediateBundle: intermediates,
		Hostname: hostname, CurrentTime: now,
	})
	if err != nil {
		return failure(classify(err))
	}
	pinStatus := "not-provided"
	if pin != nil {
		if len(result.Chain) == 0 {
			return failure("internal-failure")
		}
		root, valid := parseRootPin(result.Chain[len(result.Chain)-1].SHA256Fingerprint)
		if !valid || subtle.ConstantTimeCompare(pin, root) != 1 {
			return failure("root-pin-mismatch")
		}
		pinStatus = "matched"
	}
	return marshal(Response{
		SchemaVersion: SchemaVersion, OK: true,
		Result: &Result{
			Profile: "tls-server", Verification: "passed", Hostname: result.Hostname,
			EvaluatedAt: result.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			TrustSource: "explicit-file", RootPin: pinStatus, Revocation: "not-checked", Network: "disabled",
			IgnoredSourceRoots: ignoredRoots, Chain: result.Chain,
		},
	})
}

// parseRootPin accepts only a complete 32-byte SHA-256 fingerprint, with
// either no separators or one colon between each byte. No prefix matches.
func parseRootPin(value string) ([]byte, bool) {
	if value == "" {
		return nil, true
	}
	if len(value) == 95 {
		for index := 2; index < len(value); index += 3 {
			if value[index] != ':' {
				return nil, false
			}
		}
		value = strings.ReplaceAll(value, ":", "")
	}
	if len(value) != 64 {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	return decoded, err == nil && len(decoded) == 32
}

func withinCombinedLimit(inputs ...[]byte) bool {
	remaining := int(limits.MaxInputBytes)
	for _, input := range inputs {
		if len(input) > remaining {
			return false
		}
		remaining -= len(input)
	}
	return true
}

func classify(err error) string {
	for _, item := range []struct {
		cause error
		code  string
	}{
		{certverify.ErrInvalidHostname, "invalid-hostname"},
		{certverify.ErrInvalidCurrentTime, "invalid-time"},
		{certverify.ErrInvalidLeaf, "invalid-leaf"},
		{certverify.ErrLeafIsCA, "invalid-leaf"},
		{certverify.ErrInvalidTrustBundle, "invalid-trust-bundle"},
		{certverify.ErrRootNotCA, "invalid-trust-bundle"},
		{certverify.ErrRootNotSelfSigned, "invalid-trust-bundle"},
		{certverify.ErrInvalidIntermediateBundle, "invalid-intermediates"},
		{certverify.ErrIntermediateNotCA, "invalid-intermediates"},
		{certverify.ErrIntermediateSelfSigned, "invalid-intermediates"},
		{certverify.ErrBundleResourceLimit, "input-too-large"},
		{certverify.ErrDuplicateCertificate, "duplicate-certificate"},
		{certverify.ErrDisallowedSignatureAlgorithm, "disallowed-algorithm"},
		{certverify.ErrDisallowedPublicKey, "disallowed-algorithm"},
		{certverify.ErrHostnameMismatch, "hostname-mismatch"},
		{certverify.ErrUnknownAuthority, "unknown-authority"},
		{certverify.ErrExpired, "expired"},
		{certverify.ErrNotYetValid, "not-yet-valid"},
		{certverify.ErrIncompatibleUsage, "incompatible-usage"},
		{certverify.ErrUnhandledCritical, "unhandled-critical-extension"},
		{certverify.ErrConstraintFailure, "constraint-failure"},
	} {
		if errors.Is(err, item.cause) {
			return item.code
		}
	}
	return "verification-failed"
}

// FailureResponse covers invalid bridge requests without input reflection.
func FailureResponse(code string) string {
	switch code {
	case "invalid-browser-request", "input-too-large", "invalid-time", "internal-failure":
		return failure(code)
	default:
		return failure("internal-failure")
	}
}

func failure(code string) string {
	return marshal(Response{SchemaVersion: SchemaVersion, Error: &Failure{Code: code}})
}

func marshal(response Response) string {
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > maxResponseBytes {
		return `{"schema_version":"rootwell.browser.verify.v1","ok":false,"result":null,"error":{"code":"internal-failure"}}`
	}
	return string(encoded)
}
