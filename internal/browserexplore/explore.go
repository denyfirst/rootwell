// Package browserexplore provides a public-only browser response for the
// bounded certificate collection parser shared with the CLI.
package browserexplore

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/denyfirst/rootwell/internal/publicbundle"
)

const SchemaVersion = "rootwell.browser.explore.v1"
const maxResponseBytes = 4 << 20

type ErrorCode string

const (
	ErrorEmpty               ErrorCode = "empty-input"
	ErrorTooLarge            ErrorCode = "input-too-large"
	ErrorTooManyCertificates ErrorCode = "certificate-count-limit"
	ErrorDuplicate           ErrorCode = "duplicate-certificate"
	ErrorMetadataLimit       ErrorCode = "metadata-limit"
	ErrorUnexpectedContent   ErrorCode = "unsupported-public-bundle"
	ErrorInvalidCertificate  ErrorCode = "invalid-certificate"
	ErrorInvalidRequest      ErrorCode = "invalid-browser-request"
	ErrorInternal            ErrorCode = "internal-failure"
)

type Response struct {
	SchemaVersion string   `json:"schema_version"`
	OK            bool     `json:"ok"`
	Result        *Result  `json:"result"`
	Error         *Failure `json:"error"`
}

type Result struct {
	Count        int           `json:"count"`
	Verification string        `json:"verification"`
	TrustAnchor  string        `json:"trust_anchor"`
	Certificates []Certificate `json:"certificates"`
}

type Certificate struct {
	Encoding string `json:"encoding"`
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer"`
	IsCA     bool   `json:"is_ca"`
	NotAfter string `json:"not_after"`
	SHA256   string `json:"sha256"`
}

type Failure struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

// Process explores one public DER certificate or a strict PEM certificate
// bundle. It does not select a leaf, construct a chain, or establish trust.
func Process(input []byte) string {
	entries, err := publicbundle.Parse(input)
	if err != nil {
		return FailureResponse(classify(err))
	}
	defer func() {
		for _, entry := range entries {
			clear(entry.DER)
		}
	}()

	certificates := make([]Certificate, 0, len(entries))
	for _, entry := range entries {
		inspection := entry.Inspection
		certificates = append(certificates, Certificate{
			Encoding: string(inspection.Encoding),
			Subject:  inspection.Subject,
			Issuer:   inspection.Issuer,
			IsCA:     inspection.IsCA,
			NotAfter: inspection.NotAfter.UTC().Format(time.RFC3339),
			SHA256:   inspection.SHA256Fingerprint,
		})
	}
	return marshal(Response{
		SchemaVersion: SchemaVersion,
		OK:            true,
		Result: &Result{
			Count:        len(certificates),
			Verification: "not-performed",
			TrustAnchor:  "not-selected",
			Certificates: certificates,
		},
	})
}

// FailureResponse covers malformed JavaScript requests rejected before the
// public bundle parser receives bytes.
func FailureResponse(code ErrorCode) string {
	message := failureMessage(code)
	if message == "" {
		code = ErrorInternal
		message = failureMessage(code)
	}
	return marshal(Response{
		SchemaVersion: SchemaVersion,
		Error:         &Failure{Code: code, Message: message},
	})
}

func classify(err error) ErrorCode {
	switch {
	case errors.Is(err, publicbundle.ErrEmpty):
		return ErrorEmpty
	case errors.Is(err, publicbundle.ErrTooLarge):
		return ErrorTooLarge
	case errors.Is(err, publicbundle.ErrTooManyCertificates):
		return ErrorTooManyCertificates
	case errors.Is(err, publicbundle.ErrDuplicateCertificate):
		return ErrorDuplicate
	case errors.Is(err, publicbundle.ErrMetadataLimit):
		return ErrorMetadataLimit
	case errors.Is(err, publicbundle.ErrUnexpectedContent):
		return ErrorUnexpectedContent
	default:
		return ErrorInvalidCertificate
	}
}

func failureMessage(code ErrorCode) string {
	switch code {
	case ErrorEmpty:
		return "Choose one non-empty public certificate file."
	case ErrorTooLarge:
		return "The file exceeds the 16 MiB limit."
	case ErrorTooManyCertificates:
		return "The bundle exceeds 64 certificates."
	case ErrorDuplicate:
		return "The bundle contains a duplicate certificate."
	case ErrorMetadataLimit:
		return "Certificate metadata exceeds the display limit."
	case ErrorUnexpectedContent:
		return "Only public PEM certificate blocks or one DER certificate are supported."
	case ErrorInvalidCertificate:
		return "The file contains an invalid X.509 certificate."
	case ErrorInvalidRequest:
		return "The browser bridge rejected the request."
	case ErrorInternal:
		return "Bundle exploration could not be completed safely."
	default:
		return ""
	}
}

func marshal(response Response) string {
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > maxResponseBytes {
		return `{"schema_version":"rootwell.browser.explore.v1","ok":false,"result":null,"error":{"code":"internal-failure","message":"Bundle exploration could not be completed safely."}}`
	}
	return string(encoded)
}
