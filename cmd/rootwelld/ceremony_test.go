package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestOfflineCommandClassificationAndNoSecretArgv(t *testing.T) {
	for _, command := range []string{"recovery-enroll", "recovery-rotate", "recovery-reset", "access-snapshot", "access-verify", "access-restore"} {
		if !isOfflineCommand([]string{command}) {
			t.Fatalf("offline command %q was not classified", command)
		}
	}
	if isOfflineCommand(nil) || isOfflineCommand([]string{"serve"}) {
		t.Fatal("ordinary command classified as offline recovery")
	}
}

func TestRecoveryCodeDisplayFailureDoesNotReturnTheCode(t *testing.T) {
	const code = "secret-recovery-code"
	err := showRecoveryCode(failingWriter{}, code)
	if err == nil || strings.Contains(err.Error(), code) {
		t.Fatalf("display failure leaked code: %v", err)
	}
	var output bytes.Buffer
	if err := showRecoveryCode(&output, code); err != nil || strings.Count(output.String(), code) != 1 {
		t.Fatalf("successful display did not show code once: %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("simulated terminal failure") }
