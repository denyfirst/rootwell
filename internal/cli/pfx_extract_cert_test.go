package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/fileinput"
	"github.com/denyfirst/rootwell/internal/pfxinspect"
)

func pfxExtractFixture(t *testing.T) (string, string, []byte) {
	t.Helper()
	path := pfxInspectionFile(t)
	input, err := fileinput.ReadAtMost(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input)
	result, err := pfxinspect.Inspect(input, cliPFXPassword)
	if err != nil {
		t.Fatal(err)
	}
	der, ok := result.CertificateDER(result.MatchingCertificate.SHA256Fingerprint)
	if !ok {
		t.Fatal("matching certificate unavailable")
	}
	return path, result.MatchingCertificate.SHA256Fingerprint, der
}

func TestPFXExtractCertWritesOnlySelectedPublicCertificate(t *testing.T) {
	path, fingerprint, expected := pfxExtractFixture(t)
	for _, format := range []string{"pem", "der"} {
		t.Run(format, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "public."+format)
			var stdout, stderr bytes.Buffer
			args := []string{"pfx-extract-cert", "--output", output, "--to", format, "--sha256", fingerprint, "--input", path}
			code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) { return cliPFXPassword, nil })
			if code != ExitOK || stdout.Len() != 0 || stderr.Len() != 0 {
				t.Fatalf("extract: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			got, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if format == "pem" {
				block, trailing := pem.Decode(got)
				if block == nil || block.Type != "CERTIFICATE" || len(trailing) != 0 {
					t.Fatal("output is not one clean public PEM certificate")
				}
				got = block.Bytes
			}
			if !bytes.Equal(got, expected) {
				t.Fatal("selected certificate DER changed")
			}
			if _, err := x509.ParseCertificate(got); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(got, []byte(cliPFXPassword)) {
				t.Fatal("password reached public output")
			}
		})
	}
}

func TestPFXExtractCertBindsSelectionToAlreadyReadBytes(t *testing.T) {
	path, fingerprint, expected := pfxExtractFixture(t)
	output := filepath.Join(t.TempDir(), "selected.der")
	var stdout, stderr bytes.Buffer
	args := []string{"pfx-extract-cert", "--input", path, "--sha256", fingerprint, "--to", "der", "--output", output}
	code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("replaced during prompt"), 0o600); err != nil {
			t.Fatal(err)
		}
		return cliPFXPassword, nil
	})
	if code != ExitOK || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("snapshot selection failed: code=%d stderr=%q", code, stderr.String())
	}
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatal("selection followed the substituted input path")
	}
}

func TestPFXExtractCertRefusesWrongSelectionPasswordAndOutputCollision(t *testing.T) {
	path, fingerprint, _ := pfxExtractFixture(t)
	directory := t.TempDir()
	output := filepath.Join(directory, "public.pem")
	args := []string{"pfx-extract-cert", "--input", path, "--sha256", fingerprint, "--to", "pem", "--output", output}
	wrong := fingerprint[:94] + "0"
	if wrong == fingerprint {
		wrong = fingerprint[:94] + "1"
	}
	for _, test := range []struct {
		name     string
		args     []string
		password string
	}{
		{"wrong selection", []string{"pfx-extract-cert", "--input", path, "--sha256", wrong, "--to", "pem", "--output", output}, cliPFXPassword},
		{"wrong password", args, "wrong-password"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runWithSecretReader(test.args, &stdout, &stderr, func(string) (string, error) { return test.password, nil })
			if code != ExitFailure || stdout.Len() != 0 || strings.Contains(stderr.String(), test.password) {
				t.Fatalf("unsafe refusal: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("failure published output: %v", err)
			}
		})
	}
	if err := os.WriteFile(output, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) { return cliPFXPassword, nil }); code != ExitFailure || stdout.Len() != 0 {
		t.Fatal("existing output was accepted")
	}
	if got, _ := os.ReadFile(output); string(got) != "keep" {
		t.Fatal("existing output was overwritten")
	}
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, output); err == nil {
		stdout.Reset()
		stderr.Reset()
		if code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) { return cliPFXPassword, nil }); code != ExitFailure || stdout.Len() != 0 {
			t.Fatal("symlink output was accepted")
		}
	}
}

func TestPFXExtractCertRequiresTTYAndValidProfileBeforePrompt(t *testing.T) {
	path, fingerprint, _ := pfxExtractFixture(t)
	output := filepath.Join(t.TempDir(), "public.pem")
	args := []string{"pfx-extract-cert", "--input", path, "--sha256", fingerprint, "--to", "pem", "--output", output}
	var stdout, stderr bytes.Buffer
	if code := Run(args, &stdout, &stderr); code != ExitFailure || stdout.Len() != 0 || stderr.String() != "interactive terminal required for PFX extraction\n" {
		t.Fatalf("non-TTY accepted: code=%d stderr=%q", code, stderr.String())
	}
	bad := filepath.Join(t.TempDir(), "malformed.p12")
	if err := os.WriteFile(bad, []byte("not a PFX"), 0o600); err != nil {
		t.Fatal(err)
	}
	args[2] = bad
	stdout.Reset()
	stderr.Reset()
	if code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) { t.Fatal("bad profile prompted"); return "", nil }); code != ExitFailure || stdout.Len() != 0 || stderr.String() != "PFX profile is unsupported or outside safety limits\n" {
		t.Fatalf("bad profile accepted: code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("failure published output: %v", err)
	}
	oversized := filepath.Join(t.TempDir(), "oversized.p12")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), (1<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	args[2] = oversized
	stdout.Reset()
	stderr.Reset()
	if code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) { t.Fatal("oversized PFX prompted"); return "", nil }); code != ExitFailure || stdout.Len() != 0 || stderr.String() != "PFX exceeds 1 MiB inspection limit\n" {
		t.Fatalf("oversized PFX accepted: code=%d stderr=%q", code, stderr.String())
	}
	for _, invalid := range [][]string{
		{"pfx-extract-cert", "--input", path, "--sha256", "bad", "--to", "pem", "--output", output},
		{"pfx-extract-cert", "--input", path, "--sha256", fingerprint, "--to", "pfx", "--output", output},
		{"pfx-extract-cert", "--input", path, "--sha256", fingerprint, "--to", "pem", "--password", "secret"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := runWithSecretReader(invalid, &stdout, &stderr, func(string) (string, error) { t.Fatal("bad usage prompted"); return "", nil }); code != ExitUsage || stdout.Len() != 0 {
			t.Fatalf("bad usage accepted: code=%d", code)
		}
	}
}
