// Package cli implements Rootwell's command-line boundary.
package cli

import (
	"io"

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
  help       show this help
  version    show the build version
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

	if len(args) != 1 {
		return writeDiagnostic(stderr, "invalid arguments\n", ExitUsage)
	}

	switch args[0] {
	case "help", "-h", "--help":
		return writeRequested(stdout, stderr, helpText)
	case "version", "--version":
		return writeRequested(stdout, stderr, "rootwell "+version.Value()+"\n")
	default:
		return writeDiagnostic(stderr, "unknown command\n", ExitUsage)
	}
}

func writeRequested(stdout, stderr io.Writer, value string) int {
	if written, err := io.WriteString(stdout, value); err != nil || written != len(value) {
		_, _ = io.WriteString(stderr, "output failed\n")
		return ExitFailure
	}
	return ExitOK
}

func writeDiagnostic(stderr io.Writer, value string, code int) int {
	if written, err := io.WriteString(stderr, value); err != nil || written != len(value) {
		return ExitFailure
	}
	return code
}
