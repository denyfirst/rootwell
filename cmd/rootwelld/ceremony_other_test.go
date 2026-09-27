//go:build !linux

package main

import (
	"bytes"
	"testing"
)

func TestNonLinuxOfflineCeremonyFailsClosed(t *testing.T) {
	var output bytes.Buffer
	if err := runOfflineCommand([]string{"recovery-enroll", "unused"}, func(string) (string, error) {
		t.Fatal("unsupported ceremony read a secret")
		return "", nil
	}, &output); err == nil || output.Len() != 0 {
		t.Fatalf("unsupported ceremony changed behavior: %v", err)
	}
}
