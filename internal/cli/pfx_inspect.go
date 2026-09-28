package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/fileinput"
	"github.com/denyfirst/rootwell/internal/pfxinspect"
)

func runPFXInspect(path string, readSecret func(string) (string, error), stdout, stderr io.Writer) int {
	if readSecret == nil {
		return writeDiagnostic(stderr, "interactive terminal required for PFX inspection\n", ExitFailure)
	}
	input, err := fileinput.ReadAtMost(path, 1<<20)
	if err != nil {
		if errors.Is(err, fileinput.ErrTooLarge) {
			return writeDiagnostic(stderr, "PFX exceeds 1 MiB inspection limit\n", ExitFailure)
		}
		return writeDiagnostic(stderr, "PFX could not be read\n", ExitFailure)
	}
	defer clear(input)
	if err := pfxinspect.Preflight(input); err != nil {
		return writeDiagnostic(stderr, "PFX profile is unsupported or outside safety limits\n", ExitFailure)
	}
	password, err := readSecret("PFX password (local terminal only): ")
	if err != nil {
		return writeDiagnostic(stderr, "PFX password could not be read\n", ExitFailure)
	}
	passwordBytes := []byte(password)
	defer clear(passwordBytes)
	result, err := pfxinspect.Inspect(input, password)
	if err != nil {
		if errors.Is(err, pfxinspect.ErrUnsupported) {
			return writeDiagnostic(stderr, "PFX profile is unsupported or outside safety limits\n", ExitFailure)
		}
		return writeDiagnostic(stderr, "PFX password or contents could not be authenticated\n", ExitFailure)
	}
	return writeRequested(stdout, stderr, renderPFXInspection(result, time.Now()))
}

func renderPFXInspection(result pfxinspect.Result, now time.Time) string {
	var out strings.Builder
	fmt.Fprintln(&out, "PFX opened: one certificate matches its private key.")
	fmt.Fprintln(&out, "Private key: present; not displayed, exported, or saved.")
	fmt.Fprintln(&out, "Matching certificate:")
	writePFXPublicCertificate(&out, result.MatchingCertificate, now)
	fmt.Fprintf(&out, "Additional certificates: %d (included, not trusted)\n", len(result.Additional))
	for index, certificate := range result.Additional {
		fmt.Fprintf(&out, "Additional certificate %d:\n", index+1)
		writePFXPublicCertificate(&out, certificate, now)
	}
	fmt.Fprintln(&out, "This is not a trust, hostname, revocation, or live-server check.")
	return out.String()
}

func writePFXPublicCertificate(out *strings.Builder, certificate certinspect.Result, now time.Time) {
	window := certinspect.EvaluateTimeWindow(certificate.NotBefore, certificate.NotAfter, now)
	fmt.Fprintf(out, "  Subject: %s\n", quoteUntrusted(certificate.Subject))
	fmt.Fprintf(out, "  Issuer: %s\n", quoteUntrusted(certificate.Issuer))
	fmt.Fprintf(out, "  Expires (UTC): %s\n", certificate.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(out, "  Time window: %s (local device clock)\n", window.Status)
	fmt.Fprintf(out, "  SHA-256: %s\n", certificate.SHA256Fingerprint)
}
