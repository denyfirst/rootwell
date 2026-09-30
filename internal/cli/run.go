// Package cli implements Rootwell's command-line boundary.
package cli

import (
	"io"
	"os"
	"time"

	"github.com/denyfirst/rootwell/internal/version"
	"golang.org/x/term"
)

const (
	// ExitOK means the requested operation and its output completed.
	ExitOK = 0
	// ExitFailure means an operational or output failure occurred.
	ExitFailure = 1
	// ExitUsage means the command line did not match the public contract.
	ExitUsage = 2
)

const helpText = `usage: rootwell <command>

commands:
  help             show this help
  version          show the build version
  inspect <file>   inspect one X.509 certificate
  inspect --json <file>
                   emit versioned JSON metadata
  explore <file>   list public certificates in a PEM bundle or one DER file
  convert --input <file> --to pem|der --output <new-file>
                   convert one public X.509 certificate without overwrite
  pfx-create --cert <file> --key <file> [--chain <ordered-issuers.pem>]
                   --output <new-file>
                   create a password-protected PFX on Linux only
  pfx-inspect --input <file>
                   show public certificates from a supported modern PFX
  pfx-extract-cert --input <file> --sha256 <fingerprint>
                   --to pem|der --output <new-file>
                   save one selected public certificate; never a key or chain
  pfx-extract-key --input <file> --sha256 <matching-fingerprint>
                   --output <new-private-file>
                   export only a newly password-encrypted PKCS#8 key (Linux)
  match --cert <file> --key <file> [--json]
                   compare a certificate with an unencrypted private key
  verify <file> --trust-bundle <roots.pem> [--intermediates <chain.pem>]
                   --hostname <name>
                   verify a TLS server certificate
`

// Run executes the CLI contract using only the arguments and writers supplied
// by the caller. Command tokens are untrusted and are not reflected in errors.
func Run(args []string, stdout, stderr io.Writer) int {
	return runWithSecretReader(args, stdout, stderr, nil)
}

// RunWithTerminal enables interactive secret input only when both the input
// and output are trusted local terminals. Ordinary commands remain available
// without a terminal. Passwords never come from argv, environment, or pipes.
func RunWithTerminal(args []string, stdin, stdout, stderr *os.File) int {
	var readSecret func(string) (string, error)
	if stdin != nil && stdout != nil && term.IsTerminal(int(stdin.Fd())) && term.IsTerminal(int(stdout.Fd())) {
		readSecret = func(prompt string) (string, error) {
			if _, err := io.WriteString(stdout, prompt); err != nil {
				return "", err
			}
			raw, err := term.ReadPassword(int(stdin.Fd()))
			_, _ = io.WriteString(stdout, "\n")
			if err != nil {
				return "", err
			}
			defer clear(raw)
			return string(raw), nil
		}
	}
	return runWithSecretReader(args, stdout, stderr, readSecret)
}

func runWithSecretReader(args []string, stdout, stderr io.Writer, readSecret func(string) (string, error)) int {
	if stdout == nil || stderr == nil {
		return ExitFailure
	}

	if len(args) == 0 {
		return writeDiagnostic(stderr, "command required\n", ExitUsage)
	}

	switch args[0] {
	case "help", "-h", "--help":
		if len(args) != 1 {
			return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
		}
		return writeRequested(stdout, stderr, helpText)
	case "version", "--version":
		if len(args) != 1 {
			return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
		}
		return writeRequested(stdout, stderr, "rootwell "+version.Value()+"\n")
	case "inspect":
		switch {
		case len(args) == 2 && args[1] != "--json":
			return runInspect(args[1], inspectHuman, time.Now(), stdout, stderr)
		case len(args) == 3 && args[1] == "--json":
			return runInspect(args[2], inspectJSONOutput, time.Now(), stdout, stderr)
		default:
			return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
		}
	case "explore":
		if len(args) != 2 {
			return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
		}
		return runExplore(args[1], stdout, stderr)
	case "convert":
		arguments, ok := parseConvertArguments(args[1:])
		if !ok {
			return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
		}
		return runConvert(arguments, stderr)
	case "pfx-create":
		arguments, ok := parsePFXCreateArguments(args[1:])
		if !ok {
			return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
		}
		return runPFXCreate(arguments, readSecret, stderr)
	case "pfx-inspect":
		if len(args) != 3 || args[1] != "--input" || args[2] == "" {
			return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
		}
		return runPFXInspect(args[2], readSecret, stdout, stderr)
	case "pfx-extract-cert":
		arguments, ok := parsePFXExtractCertArguments(args[1:])
		if !ok {
			return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
		}
		return runPFXExtractCert(arguments, readSecret, stderr)
	case "pfx-extract-key":
		arguments, ok := parsePFXExtractKeyArguments(args[1:])
		if !ok {
			return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
		}
		return runPFXExtractKey(arguments, readSecret, stderr)
	case "verify":
		arguments, ok := parseVerifyArguments(args[1:])
		if !ok {
			return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
		}
		return runVerify(arguments, time.Now(), stdout, stderr)
	case "match":
		arguments, ok := parseMatchArguments(args[1:])
		if !ok {
			return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
		}
		return runMatch(arguments, stdout, stderr)
	default:
		if len(args) != 1 {
			return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
		}
		return writeDiagnostic(stderr, "unknown command\n", ExitUsage)
	}
}

func writeRequested(stdout, stderr io.Writer, value string) int {
	return writeRequestedCode(stdout, stderr, value, ExitOK)
}

func writeRequestedCode(stdout, stderr io.Writer, value string, successCode int) int {
	if written, err := io.WriteString(stdout, value); err != nil || written != len(value) {
		_, _ = io.WriteString(stderr, "output failed\n")
		return ExitFailure
	}
	return successCode
}

func writeDiagnostic(stderr io.Writer, value string, code int) int {
	if written, err := io.WriteString(stderr, value); err != nil || written != len(value) {
		return ExitFailure
	}
	return code
}
