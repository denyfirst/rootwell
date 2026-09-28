package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/pfxcreate"
)

func pfxInspectionFile(t *testing.T) string {
	t.Helper()
	certificate, key := cliPFXMaterial(t)
	data, err := pfxcreate.Create(certificate, key, nil, cliPFXPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	path := filepath.Join(t.TempDir(), "fixture.p12")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPFXInspectShowsOnlyPublicSummary(t *testing.T) {
	path := pfxInspectionFile(t)
	var stdout, stderr bytes.Buffer
	reader := func(string) (string, error) { return cliPFXPassword, nil }
	code := runWithSecretReader([]string{"pfx-inspect", "--input", path}, &stdout, &stderr, reader)
	if code != ExitOK || stderr.Len() != 0 {
		t.Fatalf("inspect: code=%d stderr=%q", code, stderr.String())
	}
	output := stdout.String()
	for _, expected := range []string{"one certificate matches", "Additional certificates: 0", "pfx.example", "Expires (UTC):", "not a trust"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("missing public explanation %q: %q", expected, output)
		}
	}
	if strings.Contains(output, cliPFXPassword) || strings.Contains(output, "BEGIN PRIVATE KEY") || strings.Contains(output, "BEGIN PFX") {
		t.Fatal("secret material reached output")
	}
}

func TestPFXInspectRefusesNonTTYAndWrongPasswordWithoutPartialOutput(t *testing.T) {
	path := pfxInspectionFile(t)
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"pfx-inspect", "--input", path}, &stdout, &stderr); code != ExitFailure || stdout.Len() != 0 || stderr.String() != "interactive terminal required for PFX inspection\n" {
		t.Fatalf("non-TTY path: code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runWithSecretReader([]string{"pfx-inspect", "--input", path}, &stdout, &stderr, func(string) (string, error) { return "wrong-password", nil }); code != ExitFailure || stdout.Len() != 0 || strings.Contains(stderr.String(), cliPFXPassword) {
		t.Fatalf("wrong password path: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runWithSecretReader([]string{"pfx-inspect", "--input", path, "--password", "secret"}, &stdout, &stderr, nil); code != ExitUsage || stdout.Len() != 0 {
		t.Fatalf("argv password accepted: code=%d", code)
	}
}

func TestPFXInspectRejectsUnsupportedBeforePasswordPrompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old-or-invalid.p12")
	if err := os.WriteFile(path, []byte("not a PFX"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	reader := func(string) (string, error) {
		t.Fatal("unsupported file requested a password")
		return "", nil
	}
	code := runWithSecretReader([]string{"pfx-inspect", "--input", path}, &stdout, &stderr, reader)
	if code != ExitFailure || stdout.Len() != 0 || stderr.String() != "PFX profile is unsupported or outside safety limits\n" {
		t.Fatalf("unsupported profile: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
