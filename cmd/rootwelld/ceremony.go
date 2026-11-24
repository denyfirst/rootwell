package main

import (
	"errors"
	"io"
	"os"

	"golang.org/x/term"
)

type secretReader func(prompt string) (string, error)

// isOfflineCommand names the commands that run with the service stopped, at a
// local terminal: each reads or prints a secret.
func isOfflineCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "key-restore", "setup-code", "serving-names", "key-export", "key-rotate", "restore":
		return true
	default:
		return false
	}
}

// handlesSecrets names the offline commands that read or print a secret: they
// run only at an interactive terminal, so nothing lands in a pipe or a log.
// serving-names prints only a public fingerprint, and may run from a script.
func handlesSecrets(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "key-restore", "setup-code", "key-export", "key-rotate", "restore":
		return true
	}
	return false
}

// readTerminalSecret never accepts a recovery code through argv, environment,
// a pipe, or a file. The Go string returned to the caller cannot be reliably
// zeroized; callers must keep it short-lived and never log it.
func readTerminalSecret(prompt string) (string, error) {
	if _, err := io.WriteString(os.Stdout, prompt); err != nil {
		return "", errors.New("secret prompt could not be shown")
	}
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = io.WriteString(os.Stdout, "\n")
	if err != nil {
		return "", errors.New("secret could not be read from the terminal")
	}
	defer clear(raw)
	if len(raw) == 0 || len(raw) > 1024 {
		return "", errors.New("secret length is invalid")
	}
	return string(raw), nil
}
