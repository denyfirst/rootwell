//go:build !linux

package cli

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestPFXExtractKeyUnsupportedPlatformRefusesBeforeInput(t *testing.T) {
	path, fingerprint, _ := pfxExtractFixture(t)
	var stdout, stderr bytes.Buffer
	args := []string{"pfx-extract-key", "--input", path, "--sha256", fingerprint, "--output", filepath.Join(t.TempDir(), "private.pem")}
	code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) {
		t.Fatal("unsupported OS prompted for secret")
		return "", nil
	})
	if code != ExitFailure || stdout.Len() != 0 || stderr.String() != "private-key export is supported on Linux only\n" {
		t.Fatalf("unsupported OS accepted: code=%d stderr=%q", code, stderr.String())
	}
}
