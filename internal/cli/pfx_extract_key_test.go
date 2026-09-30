package cli

import (
	"bytes"
	"testing"
)

func TestPFXExtractKeyRejectsNonTTYAndUnsafeArguments(t *testing.T) {
	path, fingerprint, _ := pfxExtractFixture(t)
	args := []string{"pfx-extract-key", "--input", path, "--sha256", fingerprint, "--output", "new-private.pem"}
	var stdout, stderr bytes.Buffer
	if code := Run(args, &stdout, &stderr); code != ExitFailure || stdout.Len() != 0 || stderr.String() != "interactive terminal required for private-key export\n" {
		t.Fatalf("non-TTY request accepted: code=%d stderr=%q", code, stderr.String())
	}
	for _, invalid := range [][]string{
		{"pfx-extract-key", "--input", path, "--sha256", "bad", "--output", "key.pem"},
		{"pfx-extract-key", "--input", path, "--sha256", fingerprint, "--output", "key.pem", "--password", "secret"},
		{"pfx-extract-key", "--input", path, "--sha256", fingerprint, "--output", "key.pem", "--to", "pkcs1"},
		{"pfx-extract-key", "--input", path, "--sha256", fingerprint, "--sha256", fingerprint},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := runWithSecretReader(invalid, &stdout, &stderr, func(string) (string, error) {
			t.Fatal("bad usage prompted")
			return "", nil
		}); code != ExitUsage || stdout.Len() != 0 {
			t.Fatalf("bad usage accepted: code=%d", code)
		}
	}
}
