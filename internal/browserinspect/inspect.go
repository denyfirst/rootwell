// Package browserinspect exposes a narrow, versioned browser boundary around
// the same bounded X.509 inspection core used by the CLI.
package browserinspect

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/inspectreport"
)

const SchemaVersion = "rootwell.browser.inspect.v1"

type ErrorCode string

const (
	ErrorEmpty               ErrorCode = "empty-input"
	ErrorTooLarge            ErrorCode = "input-too-large"
	ErrorUnsupportedEncoding ErrorCode = "unsupported-encoding"
	ErrorTrailingData        ErrorCode = "trailing-data"
	ErrorResourceLimit       ErrorCode = "metadata-limit"
	ErrorInvalidCertificate  ErrorCode = "invalid-certificate"
	ErrorInvalidRequest      ErrorCode = "invalid-browser-request"
	ErrorInternal            ErrorCode = "internal-failure"
)

type Response struct {
	SchemaVersion string                  `json:"schema_version"`
	OK            bool                    `json:"ok"`
	Result        *inspectreport.Document `json:"result"`
	Error         *Failure                `json:"error"`
}

type Failure struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

// Process parses one public certificate entirely in memory. Its response has
// no path, raw-input, stack-trace, or private-key field.
func Process(input []byte, now time.Time) string {
	result, err := certinspect.Inspect(input)
	if err != nil {
		return FailureResponse(classify(err))
	}
	timeWindow := certinspect.EvaluateTimeWindow(result.NotBefore, result.NotAfter, now)
	document, err := inspectreport.New(result, timeWindow)
	if err != nil {
		return FailureResponse(ErrorInternal)
	}
	return marshal(Response{
		SchemaVersion: SchemaVersion,
		OK:            true,
		Result:        &document,
	})
}

// FailureResponse is used by the WebAssembly bridge for request-shape errors
// that happen before the parser receives bytes.
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
	case errors.Is(err, certinspect.ErrEmpty):
		return ErrorEmpty
	case errors.Is(err, certinspect.ErrTooLarge):
		return ErrorTooLarge
	case errors.Is(err, certinspect.ErrUnsupportedFormat):
		return ErrorUnsupportedEncoding
	case errors.Is(err, certinspect.ErrTrailingData):
		return ErrorTrailingData
	case errors.Is(err, certinspect.ErrResourceLimit):
		return ErrorResourceLimit
	default:
		return ErrorInvalidCertificate
	}
}

func failureMessage(code ErrorCode) string {
	switch code {
	case ErrorEmpty:
		return "Choose one non-empty certificate."
	case ErrorTooLarge:
		return "The certificate exceeds the 16 MiB limit."
	case ErrorUnsupportedEncoding:
		return "Only one PEM or DER X.509 certificate is supported."
	case ErrorTrailingData:
		return "Choose exactly one complete certificate with no trailing data."
	case ErrorResourceLimit:
		return "The certificate metadata exceeds the inspection limit."
	case ErrorInvalidCertificate:
		return "The file is not a valid X.509 certificate."
	case ErrorInvalidRequest:
		return "The browser bridge rejected the request."
	case ErrorInternal:
		return "Inspection could not be completed safely."
	default:
		return ""
	}
}

func marshal(response Response) string {
	encoded, err := json.Marshal(response)
	if err != nil {
		return `{"schema_version":"rootwell.browser.inspect.v1","ok":false,"result":null,"error":{"code":"internal-failure","message":"Inspection could not be completed safely."}}`
	}
	return string(encoded)
}
