//go:build linux

package cli

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmark/pkcs8"
)

const cliExportPassword = "cli-export-password-8d130b7f"

func exportReader(value string) func(string) (string, error) {
	count := 0
	return func(string) (string, error) {
		count++
		switch count {
		case 1:
			return value, nil
		default:
			return cliExportPassword, nil
		}
	}
}

func TestPFXExtractKeyEncryptedPrivateNewFileAndOpenSSL(t *testing.T) {
	path, fingerprint, certificateDER := pfxExtractFixture(t)
	output := filepath.Join(t.TempDir(), "exported-key.pem")
	args := []string{"pfx-extract-key", "--input", path, "--sha256", fingerprint, "--output", output}
	var stdout, stderr bytes.Buffer
	if code := runWithSecretReader(args, &stdout, &stderr, exportReader(cliPFXPassword)); code != ExitOK || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("export failed: code=%d stderr=%q", code, stderr.String())
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	block, trailing := pem.Decode(data)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" || len(trailing) != 0 || len(block.Headers) != 0 {
		t.Fatal("export is not one clean encrypted PKCS#8 key")
	}
	if bytes.Contains(data, []byte(cliPFXPassword)) || bytes.Contains(data, []byte(cliExportPassword)) || bytes.Contains(data, []byte("-----BEGIN RSA PRIVATE KEY-----")) {
		t.Fatal("plaintext material reached exported file")
	}
	if info, err := os.Stat(output); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unsafe file permissions: %v, %v", info, err)
	}
	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(cliExportPassword))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("output did not contain a signing key")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	expected, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil || !bytes.Equal(publicDER, expected) {
		t.Fatal("exported private key does not match certificate")
	}
	passwordReader, passwordWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer passwordReader.Close()
	defer passwordWriter.Close()
	command := exec.Command("openssl", "pkey", "-in", output, "-passin", "fd:3", "-pubout", "-outform", "DER")
	command.ExtraFiles = []*os.File{passwordReader}
	var opensslErr bytes.Buffer
	var opensslOut bytes.Buffer
	command.Stderr = &opensslErr
	command.Stdout = &opensslOut
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := passwordWriter.WriteString(cliExportPassword + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := passwordWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("OpenSSL could not read encrypted output: %v, stderr=%q", err, opensslErr.String())
	}
	if !bytes.Equal(opensslOut.Bytes(), expected) {
		t.Fatal("OpenSSL decoded a different public key")
	}
}

func TestPFXExtractKeyRefusesWrongPasswordSelectionAndCollision(t *testing.T) {
	path, fingerprint, _ := pfxExtractFixture(t)
	output := filepath.Join(t.TempDir(), "exported-key.pem")
	args := []string{"pfx-extract-key", "--input", path, "--sha256", fingerprint, "--output", output}
	wrong := fingerprint[:94] + "0"
	if wrong == fingerprint {
		wrong = fingerprint[:94] + "1"
	}
	for _, test := range []struct {
		args   []string
		reader func(string) (string, error)
	}{
		{args, exportReader("wrong-password")},
		{[]string{"pfx-extract-key", "--input", path, "--sha256", wrong, "--output", output}, exportReader(cliPFXPassword)},
		{args, func() func(string) (string, error) {
			count := 0
			return func(string) (string, error) {
				count++
				if count == 1 {
					return cliPFXPassword, nil
				}
				if count == 2 {
					return cliExportPassword, nil
				}
				return "different-export-password-4f21", nil
			}
		}()},
		{args, func() func(string) (string, error) {
			count := 0
			return func(string) (string, error) {
				count++
				if count == 1 {
					return cliPFXPassword, nil
				}
				return "short", nil
			}
		}()},
	} {
		var stdout, stderr bytes.Buffer
		if code := runWithSecretReader(test.args, &stdout, &stderr, test.reader); code != ExitFailure || stdout.Len() != 0 || strings.Contains(stderr.String(), cliExportPassword) || strings.Contains(stderr.String(), cliPFXPassword) {
			t.Fatalf("unsafe refusal: code=%d stderr=%q", code, stderr.String())
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("failed export created output: %v", err)
		}
	}
	if err := os.WriteFile(output, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) { t.Fatal("collision prompted for password"); return "", nil }); code != ExitFailure || stdout.Len() != 0 {
		t.Fatal("existing destination was accepted")
	}
	if got, _ := os.ReadFile(output); string(got) != "keep" {
		t.Fatal("existing output was modified")
	}
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, output); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) { t.Fatal("symlink prompted for password"); return "", nil }); code != ExitFailure || stdout.Len() != 0 {
		t.Fatal("symlink destination was accepted")
	}
}

func TestPFXExtractKeyRejectsMalformedBeforePromptAndUnsafeDirectory(t *testing.T) {
	path, fingerprint, _ := pfxExtractFixture(t)
	directory := t.TempDir()
	output := filepath.Join(directory, "key.pem")
	args := []string{"pfx-extract-key", "--input", path, "--sha256", fingerprint, "--output", output}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(directory, 0o700)
	var stdout, stderr bytes.Buffer
	if code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) { t.Fatal("unsafe directory prompted"); return "", nil }); code != ExitFailure || stdout.Len() != 0 {
		t.Fatal("unsafe directory was accepted")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad.p12")
	if err := os.WriteFile(bad, []byte("not a PFX"), 0o600); err != nil {
		t.Fatal(err)
	}
	args[2] = bad
	stdout.Reset()
	stderr.Reset()
	if code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) { t.Fatal("malformed PFX prompted"); return "", nil }); code != ExitFailure || stdout.Len() != 0 || stderr.String() != "PFX profile is unsupported or outside safety limits\n" {
		t.Fatalf("malformed PFX was accepted: code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("unsafe inputs created output")
	}
}

func TestPFXExtractKeyBindsReadBeforePromptAndRejectsPasswordReuse(t *testing.T) {
	path, fingerprint, _ := pfxExtractFixture(t)
	output := filepath.Join(t.TempDir(), "exported-key.pem")
	args := []string{"pfx-extract-key", "--input", path, "--sha256", fingerprint, "--output", output}
	var stdout, stderr bytes.Buffer
	count := 0
	code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) {
		count++
		if count == 1 {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("replaced after bounded read"), 0o600); err != nil {
				t.Fatal(err)
			}
			return cliPFXPassword, nil
		}
		return cliExportPassword, nil
	})
	if code != ExitOK || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("bound input export failed: code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatal("no encrypted output from original PFX")
	}
	separateOutput := filepath.Join(t.TempDir(), "reused-password.pem")
	path, fingerprint, _ = pfxExtractFixture(t)
	args = []string{"pfx-extract-key", "--input", path, "--sha256", fingerprint, "--output", separateOutput}
	stdout.Reset()
	stderr.Reset()
	if code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) { return cliPFXPassword, nil }); code != ExitFailure || stdout.Len() != 0 || stderr.String() != "new key password must differ from PFX password\n" {
		t.Fatalf("password reuse accepted: code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Lstat(separateOutput); !os.IsNotExist(err) {
		t.Fatal("password reuse produced an output")
	}
}
