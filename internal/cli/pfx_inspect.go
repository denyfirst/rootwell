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

var errPFXInspectionTimeout = errors.New("PFX inspection exceeded time budget")

const pfxInspectionTimeout = 10 * time.Second

func runPFXInspect(path string, readSecret func(string) (string, error), stdout, stderr io.Writer) int {
	result, code := openPFX(path, readSecret, stderr, "inspection")
	if code != ExitOK {
		return code
	}
	return writeRequested(stdout, stderr, renderPFXInspection(result, time.Now()))
}

// openPFX is the one-shot local CLI admission boundary shared by public
// inspection and public certificate extraction. It must not run in a daemon.
func openPFX(path string, readSecret func(string) (string, error), stderr io.Writer, operation string) (pfxinspect.Result, int) {
	if readSecret == nil {
		return pfxinspect.Result{}, writeDiagnostic(stderr, "interactive terminal required for PFX "+operation+"\n", ExitFailure)
	}
	input, err := fileinput.ReadAtMost(path, 1<<20)
	if err != nil {
		if errors.Is(err, fileinput.ErrTooLarge) {
			return pfxinspect.Result{}, writeDiagnostic(stderr, "PFX exceeds 1 MiB inspection limit\n", ExitFailure)
		}
		return pfxinspect.Result{}, writeDiagnostic(stderr, "PFX could not be read\n", ExitFailure)
	}
	if err := pfxinspect.Preflight(input); err != nil {
		clear(input)
		return pfxinspect.Result{}, writeDiagnostic(stderr, "PFX profile is unsupported or outside safety limits\n", ExitFailure)
	}
	password, err := readSecret("PFX password (local terminal only): ")
	if err != nil {
		clear(input)
		return pfxinspect.Result{}, writeDiagnostic(stderr, "PFX password could not be read\n", ExitFailure)
	}
	passwordBytes := []byte(password)
	defer clear(passwordBytes)
	// The worker owns and clears input. On timeout, a one-shot CLI process
	// returns to main and exits; the decoder itself has no cancellation API.
	result, err := inspectPFXWithDeadline(input, password, pfxInspectionTimeout, pfxinspect.Inspect)
	if err != nil {
		if errors.Is(err, errPFXInspectionTimeout) {
			return pfxinspect.Result{}, writeDiagnostic(stderr, "PFX inspection exceeded safety time limit\n", ExitFailure)
		}
		if errors.Is(err, pfxinspect.ErrUnsupported) {
			return pfxinspect.Result{}, writeDiagnostic(stderr, "PFX profile is unsupported or outside safety limits\n", ExitFailure)
		}
		return pfxinspect.Result{}, writeDiagnostic(stderr, "PFX password or contents could not be authenticated\n", ExitFailure)
	}
	return result, ExitOK
}

func inspectPFXWithDeadline(input []byte, password string, budget time.Duration, decode func([]byte, string) (pfxinspect.Result, error)) (pfxinspect.Result, error) {
	type outcome struct {
		result pfxinspect.Result
		err    error
	}
	completed := make(chan outcome, 1)
	go func() {
		var result pfxinspect.Result
		var err error
		defer func() {
			if recover() != nil {
				result = pfxinspect.Result{}
				err = pfxinspect.ErrInvalid
			}
			clear(input)
			completed <- outcome{result: result, err: err}
		}()
		result, err = decode(input, password)
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case output := <-completed:
		return output.result, output.err
	case <-timer.C:
		return pfxinspect.Result{}, errPFXInspectionTimeout
	}
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
