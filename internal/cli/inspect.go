package cli

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/fileinput"
)

type inspectOutput int

const (
	inspectHuman inspectOutput = iota
	inspectJSONOutput
)

func runInspect(path string, outputFormat inspectOutput, now time.Time, stdout, stderr io.Writer) int {
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
	timeWindow := certinspect.EvaluateTimeWindow(result.NotBefore, result.NotAfter, now)

	if outputFormat == inspectJSONOutput {
		output, renderErr := renderCertificateJSON(result, timeWindow)
		if renderErr != nil {
			return writeDiagnostic(stderr, "output encoding failed\n", ExitFailure)
		}
		return writeRequested(stdout, stderr, output)
	}
	return writeRequested(stdout, stderr, renderCertificate(result, timeWindow))
}

func renderCertificate(result certinspect.Result, timeWindow certinspect.TimeWindow) string {
	var output strings.Builder
	fmt.Fprintln(&output, "type: x509-certificate")
	fmt.Fprintf(&output, "encoding: %s\n", result.Encoding)
	fmt.Fprintf(&output, "subject: %s\n", quoteUntrusted(result.Subject))
	fmt.Fprintf(&output, "issuer: %s\n", quoteUntrusted(result.Issuer))
	fmt.Fprintf(&output, "serial: %s\n", result.Serial)
	fmt.Fprintf(&output, "not-before: %s\n", result.NotBefore.UTC().Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(&output, "not-after: %s\n", result.NotAfter.UTC().Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(&output, "time-window-status: %s\n", timeWindow.Status)
	fmt.Fprintf(&output, "evaluated-at: %s\n", timeWindow.EvaluatedAt.UTC().Format(time.RFC3339Nano))
	writeRelativeTime(&output, "seconds-until-start", "whole-days-until-start", timeWindow.SecondsUntilStart)
	writeRelativeTime(&output, "seconds-until-expiry", "whole-days-until-expiry", timeWindow.SecondsUntilExpiry)
	writeRelativeTime(&output, "seconds-since-expiry", "whole-days-since-expiry", timeWindow.SecondsSinceExpiry)
	fmt.Fprintf(&output, "public-key-algorithm: %s\n", result.PublicKeyAlgorithm)
	fmt.Fprintf(&output, "public-key-bits: %d\n", result.PublicKeyBits)
	if result.PublicKeyCurve != "" {
		fmt.Fprintf(&output, "public-key-curve: %s\n", result.PublicKeyCurve)
	}
	fmt.Fprintf(&output, "signature-algorithm: %s\n", result.SignatureAlgorithm)
	fmt.Fprintf(&output, "basic-constraints-present: %t\n", result.BasicConstraintsValid)
	fmt.Fprintf(&output, "is-ca: %t\n", result.IsCA)
	if result.MaxPathLength != nil {
		fmt.Fprintf(&output, "max-path-length: %d\n", *result.MaxPathLength)
	}
	fmt.Fprintf(&output, "sha256: %s\n", result.SHA256Fingerprint)
	if result.SubjectKeyID != "" {
		fmt.Fprintf(&output, "subject-key-id: %s\n", result.SubjectKeyID)
	}
	if result.AuthorityKeyID != "" {
		fmt.Fprintf(&output, "authority-key-id: %s\n", result.AuthorityKeyID)
	}
	writeQuotedValues(&output, "key-usage", result.KeyUsage)
	writeQuotedValues(&output, "extended-key-usage", result.ExtendedKeyUsage)
	writeQuotedValues(&output, "unknown-extended-key-usage", result.UnknownExtendedKeyUsage)
	writeQuotedValues(&output, "critical-extension", result.CriticalExtensions)
	writeQuotedValues(&output, "unhandled-critical-extension", result.UnhandledCriticalExtensions)
	writeQuotedValues(&output, "dns-san", result.DNSNames)
	writeQuotedValues(&output, "email-san", result.EmailAddresses)
	writeQuotedValues(&output, "ip-san", result.IPAddresses)
	writeQuotedValues(&output, "uri-san", result.URIs)
	return output.String()
}

func writeRelativeTime(output *strings.Builder, secondsLabel, daysLabel string, seconds *int64) {
	if seconds == nil {
		return
	}
	fmt.Fprintf(output, "%s: %d\n", secondsLabel, *seconds)
	fmt.Fprintf(output, "%s: %d\n", daysLabel, *seconds/86400)
}

func writeQuotedValues(output *strings.Builder, label string, values []string) {
	for _, value := range values {
		fmt.Fprintf(output, "%s: %s\n", label, quoteUntrusted(value))
	}
}

func quoteUntrusted(value string) string {
	return strconv.QuoteToASCII(value)
}
