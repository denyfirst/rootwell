//go:build linux

package pfxinspect

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestInspectModernOpenSSLGeneratedPFX(t *testing.T) {
	_, certificate, key := fixture(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyDER)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")
	outputPath := filepath.Join(dir, "openssl.p12")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	passwordReader, passwordWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer passwordReader.Close()
	defer passwordWriter.Close()
	command := exec.Command("openssl", "pkcs12", "-export", "-inkey", keyPath, "-in", certPath, "-out", outputPath, "-passout", "fd:3")
	command.ExtraFiles = []*os.File{passwordReader}
	if err := command.Start(); err != nil {
		t.Fatalf("OpenSSL start: %v", err)
	}
	if _, err := passwordWriter.WriteString(testPassword + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := passwordWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("OpenSSL PFX creation failed: %v", err)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	result, err := Inspect(data, testPassword)
	if err != nil || result.MatchingCertificate.Subject != certificate.Subject.String() {
		t.Fatalf("OpenSSL modern PFX was not inspected: %v", err)
	}
}
