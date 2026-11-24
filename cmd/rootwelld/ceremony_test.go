package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestOfflineCommandClassificationAndNoSecretArgv(t *testing.T) {
	for _, command := range []string{"key-restore", "setup-code", "serving-names"} {
		if !isOfflineCommand([]string{command}) {
			t.Fatalf("offline command %q was not classified", command)
		}
	}
	// The access-file ceremonies and the old inventory ceremonies are gone:
	// accounts and certificates live in the vault now.
	for _, command := range []string{"serve", "init", "inventory-init", "inventory-restore", "recovery-enroll", "recovery-rotate", "recovery-reset", "access-snapshot", "access-verify", "access-restore"} {
		if isOfflineCommand([]string{command}) {
			t.Fatalf("%q classified as an offline command", command)
		}
	}
	for command, secret := range map[string]bool{"key-restore": true, "setup-code": true, "serving-names": false} {
		if handlesSecrets([]string{command}) != secret {
			t.Fatalf("%q handles secrets: %v", command, !secret)
		}
	}
	if isOfflineCommand(nil) {
		t.Fatal("no command classified as offline")
	}
}

func TestSetupCodeDisplayFailureDoesNotReturnTheCode(t *testing.T) {
	const code = "secret-setup-code"
	until := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	for _, name := range []string{"", "ada"} {
		err := showSetupCode(failingWriter{}, code, until, name)
		if err == nil || strings.Contains(err.Error(), code) {
			t.Fatalf("display failure leaked the code: %v", err)
		}
		var output bytes.Buffer
		if err := showSetupCode(&output, code, until, name); err != nil || strings.Count(output.String(), code) != 1 || !strings.Contains(output.String(), "2026-11-25 12:00") {
			t.Fatalf("successful display did not show the code once with its end: %v", err)
		}
		if name != "" && !strings.Contains(output.String(), "the name "+name) {
			t.Fatal("a reset code does not say which account it replaces")
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("simulated terminal failure") }
