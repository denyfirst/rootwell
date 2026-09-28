package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const cliPFXPassword = "S1nce-2026-Rootwell-test-9A3f"

func cliPFXMaterial(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(44), Subject: pkix.Name{CommonName: "pfx.example"}, DNSNames: []string{"pfx.example"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return cert, encodedKey
}

func TestPFXCreateRequiresSecretReaderBeforeKeyRead(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"pfx-create", "--cert", "missing", "--key", "missing", "--output", "output.p12"}, &stdout, &stderr)
	if code != ExitFailure || stderr.String() != "interactive terminal required for PFX creation\n" || stdout.Len() != 0 {
		t.Fatalf("non-interactive path: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPFXCreateInteractiveAndNoOverwrite(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secret output is Linux-only")
	}
	dir := t.TempDir()
	cert, key := cliPFXMaterial(t)
	certPath, keyPath, outputPath := filepath.Join(dir, "cert.der"), filepath.Join(dir, "key.der"), filepath.Join(dir, "identity.p12")
	if err := os.WriteFile(certPath, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"pfx-create", "--output", outputPath, "--key", keyPath, "--cert", certPath}
	readCount := 0
	reader := func(string) (string, error) { readCount++; return cliPFXPassword, nil }
	var stdout, stderr bytes.Buffer
	if code := runWithSecretReader(args, &stdout, &stderr, reader); code != ExitOK || stdout.Len() != 0 || stderr.Len() != 0 || readCount != 2 {
		t.Fatalf("create: code=%d stdout=%q stderr=%q prompts=%d", code, stdout.String(), stderr.String(), readCount)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	_, decoded, _, err := pkcs12.DecodeChain(data, cliPFXPassword)
	if err != nil || !bytes.Equal(decoded.Raw, cert) {
		t.Fatalf("output did not decode equivalently: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runWithSecretReader(args, &stdout, &stderr, reader); code != ExitFailure || stdout.Len() != 0 || !strings.Contains(stderr.String(), "unsafe") {
		t.Fatalf("overwrite accepted: code=%d stderr=%q", code, stderr.String())
	}
	if readCount != 2 {
		t.Fatal("overwrite attempt prompted for a secret before refusing destination")
	}
	if after, err := os.ReadFile(outputPath); err != nil || !bytes.Equal(after, data) {
		t.Fatal("existing PFX changed")
	}
}

func TestPFXCreateRefusesPasswordMismatchAndBadUsage(t *testing.T) {
	for _, args := range [][]string{
		{"pfx-create"},
		{"pfx-create", "--cert", "c", "--key", "k", "--output", "o", "--password", "secret"},
		{"pfx-create", "--cert", "c", "--cert", "c", "--key", "k"},
	} {
		var stdout, stderr bytes.Buffer
		if code := runWithSecretReader(args, &stdout, &stderr, func(string) (string, error) { t.Fatal("prompted for bad usage"); return "", nil }); code != ExitUsage || stdout.Len() != 0 {
			t.Fatalf("usage accepted: %v code=%d", args, code)
		}
	}
	if runtime.GOOS != "linux" {
		return
	}
	cert, key := cliPFXMaterial(t)
	dir := t.TempDir()
	certPath, keyPath, outputPath := filepath.Join(dir, "cert"), filepath.Join(dir, "key"), filepath.Join(dir, "output")
	if err := os.WriteFile(certPath, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	count := 0
	reader := func(string) (string, error) {
		count++
		if count == 1 {
			return cliPFXPassword, nil
		}
		return cliPFXPassword + "different", nil
	}
	var stdout, stderr bytes.Buffer
	if code := runWithSecretReader([]string{"pfx-create", "--cert", certPath, "--key", keyPath, "--output", outputPath}, &stdout, &stderr, reader); code != ExitFailure || stderr.String() != "PFX passwords do not match\n" || stdout.Len() != 0 {
		t.Fatalf("mismatch accepted: code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("output after mismatch: %v", err)
	}
	if strings.Contains(stderr.String(), cliPFXPassword) {
		t.Fatal("password leaked")
	}
}

func TestPFXCreateUnsupportedOSRefusesBeforeKeyRead(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux has a reviewed secret output path")
	}
	var stdout, stderr bytes.Buffer
	reader := func(string) (string, error) { t.Fatal("password was requested"); return "", nil }
	code := runWithSecretReader([]string{"pfx-create", "--cert", "missing-cert", "--key", "missing-key", "--output", "missing-output"}, &stdout, &stderr, reader)
	if code != ExitFailure || stderr.String() != "PFX file creation is supported on Linux only\n" || stdout.Len() != 0 {
		t.Fatalf("unsupported platform: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
