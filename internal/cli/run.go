// Package cli implements Rootwell's command-line boundary.
package cli

import (
	"io"
	"time"

	"github.com/denyfirst/rootwell/internal/version"
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
  match --cert <file> --key <file> [--json]
                   compare a certificate with an unencrypted private key
  verify <file> --trust-bundle <roots.pem> [--intermediates <chain.pem>]
                   --hostname <name>
                   verify a TLS server certificate
`

// Run executes the CLI contract using only the arguments and writers supplied
// by the caller. Command tokens are untrusted and are not reflected in errors.
func Run(args []string, stdout, stderr io.Writer) int {
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
