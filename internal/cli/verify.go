package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/certverify"
	"github.com/denyfirst/rootwell/internal/fileinput"
)

type verifyArguments struct {
	leafPath         string
	trustBundlePath  string
	intermediatePath string
	hostname         string
}

func parseVerifyArguments(args []string) (verifyArguments, bool) {
	if len(args) < 5 || len(args)%2 == 0 || args[0] == "" {
		return verifyArguments{}, false
	}
	parsed := verifyArguments{leafPath: args[0]}
	for index := 1; index < len(args); index += 2 {
		flag, value := args[index], args[index+1]
		if value == "" {
			return verifyArguments{}, false
		}
		switch flag {
		case "--trust-bundle":
			if parsed.trustBundlePath != "" {
				return verifyArguments{}, false
			}
			parsed.trustBundlePath = value
		case "--intermediates":
			if parsed.intermediatePath != "" {
				return verifyArguments{}, false
			}
			parsed.intermediatePath = value
		case "--hostname":
			if parsed.hostname != "" {
				return verifyArguments{}, false
			}
			parsed.hostname = value
		default:
			return verifyArguments{}, false
		}
	}
	if parsed.trustBundlePath == "" || parsed.hostname == "" {
		return verifyArguments{}, false
	}
	return parsed, true
}

func runVerify(arguments verifyArguments, now time.Time, stdout, stderr io.Writer) int {
	leaf, err := readVerificationInput(arguments.leafPath, "certificate", stderr)
	if err != nil {
		return ExitFailure
	}
	trustBundle, err := readVerificationInput(arguments.trustBundlePath, "trust bundle", stderr)
	if err != nil {
		return ExitFailure
	}
	var intermediateBundle []byte
	if arguments.intermediatePath != "" {
		intermediateBundle, err = readVerificationInput(arguments.intermediatePath, "intermediate bundle", stderr)
		if err != nil {
			return ExitFailure
		}
	}

	result, err := certverify.Verify(leaf, certverify.Options{
		TrustBundle:        trustBundle,
		IntermediateBundle: intermediateBundle,
		Hostname:           arguments.hostname,
		CurrentTime:        now,
	})
	if err != nil {
		return writeDiagnostic(stderr, verificationDiagnostic(err), ExitFailure)
	}
	return writeRequested(stdout, stderr, renderVerification(result))
}

func readVerificationInput(path, label string, stderr io.Writer) ([]byte, error) {
	input, err := fileinput.Read(path)
	if err == nil {
		return input, nil
	}
	message := label + " could not be read\n"
	if errors.Is(err, fileinput.ErrEmpty) {
		message = label + " is empty\n"
	} else if errors.Is(err, fileinput.ErrTooLarge) {
		message = label + " exceeds 16 MiB limit\n"
	}
	writeDiagnostic(stderr, message, ExitFailure)
	return nil, err
}

func verificationDiagnostic(err error) string {
	switch {
	case errors.Is(err, certverify.ErrInvalidHostname):
		return "verification failed: invalid hostname\n"
	case errors.Is(err, certverify.ErrInvalidCurrentTime):
		return "verification failed: invalid evaluation time\n"
	case errors.Is(err, certverify.ErrInvalidLeaf), errors.Is(err, certverify.ErrLeafIsCA):
		return "verification failed: invalid leaf certificate\n"
	case errors.Is(err, certverify.ErrInvalidTrustBundle),
		errors.Is(err, certverify.ErrRootNotCA),
		errors.Is(err, certverify.ErrRootNotSelfSigned):
		return "verification failed: invalid trust bundle\n"
	case errors.Is(err, certverify.ErrInvalidIntermediateBundle),
		errors.Is(err, certverify.ErrIntermediateNotCA),
		errors.Is(err, certverify.ErrIntermediateSelfSigned):
		return "verification failed: invalid intermediate bundle\n"
	case errors.Is(err, certverify.ErrBundleResourceLimit):
		return "verification failed: bundle resource limit\n"
	case errors.Is(err, certverify.ErrDuplicateCertificate):
		return "verification failed: duplicate certificate\n"
	case errors.Is(err, certverify.ErrDisallowedSignatureAlgorithm):
		return "verification failed: disallowed signature algorithm\n"
	case errors.Is(err, certverify.ErrDisallowedPublicKey):
		return "verification failed: disallowed public key\n"
	case errors.Is(err, certverify.ErrHostnameMismatch):
		return "verification failed: hostname mismatch\n"
	case errors.Is(err, certverify.ErrUnknownAuthority):
		return "verification failed: unknown authority\n"
	case errors.Is(err, certverify.ErrExpired):
		return "verification failed: expired certificate\n"
	case errors.Is(err, certverify.ErrNotYetValid):
		return "verification failed: certificate is not yet valid\n"
	case errors.Is(err, certverify.ErrIncompatibleUsage):
		return "verification failed: incompatible key usage\n"
	case errors.Is(err, certverify.ErrUnhandledCritical):
		return "verification failed: unhandled critical extension\n"
	case errors.Is(err, certverify.ErrConstraintFailure):
		return "verification failed: certificate constraint\n"
	default:
		return "verification failed\n"
	}
}

func renderVerification(result certverify.Result) string {
	var output strings.Builder
	fmt.Fprintln(&output, "verification: passed")
	fmt.Fprintln(&output, "profile: tls-server")
	fmt.Fprintf(&output, "hostname: %s\n", quoteUntrusted(result.Hostname))
	fmt.Fprintf(&output, "evaluated-at: %s\n", result.EvaluatedAt.UTC().Format(time.RFC3339Nano))
	fmt.Fprintf(&output, "chain-depth: %d\n", len(result.Chain))
	fmt.Fprintln(&output, "revocation: not-checked")
	fmt.Fprintln(&output, "network: disabled")
	for index, certificate := range result.Chain {
		fmt.Fprintf(&output, "chain-%d-subject: %s\n", index, quoteUntrusted(certificate.Subject))
		fmt.Fprintf(&output, "chain-%d-issuer: %s\n", index, quoteUntrusted(certificate.Issuer))
		fmt.Fprintf(&output, "chain-%d-sha256: %s\n", index, certificate.SHA256Fingerprint)
	}
	return output.String()
}
