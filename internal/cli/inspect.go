package cli

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/fileinput"
)

func runInspect(path string, stdout, stderr io.Writer) int {
	input, err := fileinput.Read(path)
	if err != nil {
		switch {
		case errors.Is(err, fileinput.ErrEmpty):
			return writeDiagnostic(stderr, "input is empty\n", ExitFailure)
		case errors.Is(err, fileinput.ErrTooLarge):
			return writeDiagnostic(stderr, "input exceeds 16 MiB limit\n", ExitFailure)
		default:
			return writeDiagnostic(stderr, "input could not be read\n", ExitFailure)
		}
	}

	result, err := certinspect.Inspect(input)
	if err != nil {
		switch {
		case errors.Is(err, certinspect.ErrEmpty):
			return writeDiagnostic(stderr, "input is empty\n", ExitFailure)
		case errors.Is(err, certinspect.ErrTooLarge):
			return writeDiagnostic(stderr, "input exceeds 16 MiB limit\n", ExitFailure)
		case errors.Is(err, certinspect.ErrUnsupportedFormat):
			return writeDiagnostic(stderr, "unsupported certificate encoding\n", ExitFailure)
		case errors.Is(err, certinspect.ErrTrailingData):
			return writeDiagnostic(stderr, "certificate contains trailing data\n", ExitFailure)
		case errors.Is(err, certinspect.ErrResourceLimit):
			return writeDiagnostic(stderr, "certificate metadata exceeds limit\n", ExitFailure)
		default:
			return writeDiagnostic(stderr, "invalid x509 certificate\n", ExitFailure)
		}
	}

	return writeRequested(stdout, stderr, renderCertificate(result))
}

func renderCertificate(result certinspect.Result) string {
	var output strings.Builder
	fmt.Fprintln(&output, "type: x509-certificate")
	fmt.Fprintf(&output, "encoding: %s\n", result.Encoding)
	fmt.Fprintf(&output, "subject: %s\n", quoteUntrusted(result.Subject))
	fmt.Fprintf(&output, "issuer: %s\n", quoteUntrusted(result.Issuer))
	fmt.Fprintf(&output, "serial: %s\n", result.Serial)
	fmt.Fprintf(&output, "not-before: %s\n", result.NotBefore.UTC().Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(&output, "not-after: %s\n", result.NotAfter.UTC().Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(&output, "public-key-algorithm: %s\n", result.PublicKeyAlgorithm)
	fmt.Fprintf(&output, "signature-algorithm: %s\n", result.SignatureAlgorithm)
	fmt.Fprintf(&output, "is-ca: %t\n", result.IsCA)
	fmt.Fprintf(&output, "sha256: %s\n", result.SHA256Fingerprint)
	writeQuotedValues(&output, "dns-san", result.DNSNames)
	writeQuotedValues(&output, "email-san", result.EmailAddresses)
	writeQuotedValues(&output, "ip-san", result.IPAddresses)
	writeQuotedValues(&output, "uri-san", result.URIs)
	return output.String()
}

func writeQuotedValues(output *strings.Builder, label string, values []string) {
	for _, value := range values {
		fmt.Fprintf(output, "%s: %s\n", label, quoteUntrusted(value))
	}
}

func quoteUntrusted(value string) string {
	return strconv.QuoteToASCII(value)
}
