package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/fileinput"
	"github.com/denyfirst/rootwell/internal/publicbundle"
)

func runExplore(path string, stdout, stderr io.Writer) int {
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

	entries, err := publicbundle.Parse(input)
	if err != nil {
		switch {
		case errors.Is(err, publicbundle.ErrTooLarge):
			return writeDiagnostic(stderr, "input exceeds 16 MiB limit\n", ExitFailure)
		case errors.Is(err, publicbundle.ErrTooManyCertificates):
			return writeDiagnostic(stderr, "bundle exceeds 64 certificates\n", ExitFailure)
		case errors.Is(err, publicbundle.ErrDuplicateCertificate):
			return writeDiagnostic(stderr, "bundle contains duplicate certificates\n", ExitFailure)
		case errors.Is(err, publicbundle.ErrMetadataLimit):
			return writeDiagnostic(stderr, "certificate metadata exceeds limit\n", ExitFailure)
		default:
			return writeDiagnostic(stderr, "input is not a supported public certificate bundle\n", ExitFailure)
		}
	}
	return writeRequested(stdout, stderr, renderExplore(entries))
}

func renderExplore(entries []publicbundle.Entry) string {
	var output strings.Builder
	fmt.Fprintln(&output, "type: public-certificate-collection")
	fmt.Fprintf(&output, "certificates: %d\n", len(entries))
	fmt.Fprintln(&output, "verification: not-performed")
	fmt.Fprintln(&output, "trust-anchor: not-selected")
	for index, entry := range entries {
		result := entry.Inspection
		fmt.Fprintf(&output, "certificate-%d-encoding: %s\n", index+1, result.Encoding)
		fmt.Fprintf(&output, "certificate-%d-subject: %s\n", index+1, quoteUntrusted(result.Subject))
		fmt.Fprintf(&output, "certificate-%d-issuer: %s\n", index+1, quoteUntrusted(result.Issuer))
		fmt.Fprintf(&output, "certificate-%d-is-ca: %t\n", index+1, result.IsCA)
		fmt.Fprintf(&output, "certificate-%d-not-after: %s\n", index+1, result.NotAfter.UTC().Format(time.RFC3339))
		fmt.Fprintf(&output, "certificate-%d-sha256: %s\n", index+1, result.SHA256Fingerprint)
	}
	return output.String()
}
