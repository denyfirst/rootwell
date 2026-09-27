package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

type secretReader func(prompt string) (string, error)

func isOfflineCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "recovery-enroll", "recovery-rotate", "recovery-reset", "access-snapshot", "access-verify", "access-restore":
		return true
	default:
		return false
	}
}

// readTerminalSecret never accepts a password or recovery code through argv,
// environment, a pipe, or a file. The Go string returned to the caller cannot
// be reliably zeroized; callers must keep it short-lived and never log it.
func readTerminalSecret(prompt string) (string, error) {
	if _, err := io.WriteString(os.Stdout, prompt); err != nil {
		return "", errors.New("secret prompt could not be shown")
	}
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = io.WriteString(os.Stdout, "\n")
	if err != nil {
		return "", errors.New("secret could not be read from the terminal")
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	if len(raw) == 0 || len(raw) > 1024 {
		return "", errors.New("secret length is invalid")
	}
	return string(raw), nil
}

func showRecoveryCode(out io.Writer, code string) error {
	if _, err := fmt.Fprintf(out, "Recovery code (shown once; store separately from snapshots and this host):\n\n  %s\n\n", code); err != nil {
		return errors.New("recovery code could not be displayed; use the known login password to rotate recovery")
	}
	return nil
}
