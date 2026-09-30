package cli

import (
	"crypto/subtle"
	"errors"
	"io"

	"github.com/denyfirst/rootwell/internal/fileinput"
	"github.com/denyfirst/rootwell/internal/pfxinspect"
	"github.com/denyfirst/rootwell/internal/pfxkeyexport"
	"github.com/denyfirst/rootwell/internal/secretfile"
)

type pfxExtractKeyArguments struct {
	input       string
	fingerprint string
	output      string
}

func parsePFXExtractKeyArguments(args []string) (pfxExtractKeyArguments, bool) {
	if len(args) != 6 {
		return pfxExtractKeyArguments{}, false
	}
	var parsed pfxExtractKeyArguments
	seen := make(map[string]bool)
	for index := 0; index < len(args); index += 2 {
		flag, value := args[index], args[index+1]
		if value == "" || seen[flag] {
			return pfxExtractKeyArguments{}, false
		}
		seen[flag] = true
		switch flag {
		case "--input":
			parsed.input = value
		case "--sha256":
			parsed.fingerprint = value
		case "--output":
			parsed.output = value
		default:
			return pfxExtractKeyArguments{}, false
		}
	}
	return parsed, parsed.input != "" && parsed.output != "" && pfxinspect.ValidFingerprint(parsed.fingerprint)
}

func runPFXExtractKey(args pfxExtractKeyArguments, readSecret func(string) (string, error), stderr io.Writer) int {
	if readSecret == nil {
		return writeDiagnostic(stderr, "interactive terminal required for private-key export\n", ExitFailure)
	}
	if err := secretfile.Preflight(args.output); err != nil {
		if errors.Is(err, secretfile.ErrUnsupported) {
			return writeDiagnostic(stderr, "private-key export is supported on Linux only\n", ExitFailure)
		}
		return writeDiagnostic(stderr, "private output directory or destination is unsafe\n", ExitFailure)
	}
	input, err := fileinput.ReadAtMost(args.input, 1<<20)
	if err != nil {
		if errors.Is(err, fileinput.ErrTooLarge) {
			return writeDiagnostic(stderr, "PFX exceeds 1 MiB inspection limit\n", ExitFailure)
		}
		return writeDiagnostic(stderr, "PFX could not be read\n", ExitFailure)
	}
	if err := pfxinspect.Preflight(input); err != nil {
		clear(input)
		return writeDiagnostic(stderr, "PFX profile is unsupported or outside safety limits\n", ExitFailure)
	}
	pfxPassword, err := readSecret("PFX password (local terminal only): ")
	if err != nil {
		clear(input)
		return writeDiagnostic(stderr, "PFX password could not be read\n", ExitFailure)
	}
	newPassword, err := readSecret("Sensitive key export: new password (20-128 printable ASCII, not the PFX/login password): ")
	if err != nil {
		clear(input)
		return writeDiagnostic(stderr, "new key password could not be read\n", ExitFailure)
	}
	confirmation, err := readSecret("Confirm new key password: ")
	if err != nil {
		clear(input)
		return writeDiagnostic(stderr, "new key password could not be read\n", ExitFailure)
	}
	first, second, old := []byte(newPassword), []byte(confirmation), []byte(pfxPassword)
	defer clear(first)
	defer clear(second)
	defer clear(old)
	if len(first) != len(second) || subtle.ConstantTimeCompare(first, second) != 1 {
		clear(input)
		return writeDiagnostic(stderr, "new key passwords do not match\n", ExitFailure)
	}
	if len(first) == len(old) && subtle.ConstantTimeCompare(first, old) == 1 {
		clear(input)
		return writeDiagnostic(stderr, "new key password must differ from PFX password\n", ExitFailure)
	}
	// The worker owns input and its own output-password copy. On timeout the
	// one-shot CLI must exit; this decoder cannot run in a daemon.
	workerPassword := append([]byte(nil), first...)
	output, err := pfxWithDeadline(input, pfxPassword, pfxInspectionTimeout, func(data []byte, password string) ([]byte, error) {
		defer clear(workerPassword)
		return pfxkeyexport.Export(data, password, args.fingerprint, workerPassword)
	})
	if err != nil {
		if errors.Is(err, errPFXInspectionTimeout) {
			return writeDiagnostic(stderr, "PFX extraction exceeded safety time limit\n", ExitFailure)
		}
		if errors.Is(err, pfxkeyexport.ErrExportPassword) {
			return writeDiagnostic(stderr, "new key password does not meet policy\n", ExitFailure)
		}
		return writeDiagnostic(stderr, "PFX password, selected certificate, or key contents were invalid\n", ExitFailure)
	}
	defer clear(output)
	if err := secretfile.WriteNew(args.output, output); err != nil {
		if errors.Is(err, secretfile.ErrUncertain) {
			return writeDiagnostic(stderr, "private output state is uncertain; inspect destination before retry\n", ExitFailure)
		}
		return writeDiagnostic(stderr, "private output directory or destination is unsafe\n", ExitFailure)
	}
	return ExitOK
}
