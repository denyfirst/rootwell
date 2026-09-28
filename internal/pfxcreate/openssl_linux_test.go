//go:build linux

package pfxcreate

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCreatedPFXOpensInIndependentOpenSSL(t *testing.T) {
	leaf, key, _, _ := testMaterial(t)
	output, err := Create(leaf, key, nil, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(output)
	path := filepath.Join(t.TempDir(), "generated.p12")
	if err := os.WriteFile(path, output, 0o600); err != nil {
		t.Fatal(err)
	}
	passwordReader, passwordWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer passwordReader.Close()
	defer passwordWriter.Close()
	command := exec.Command("openssl", "pkcs12", "-in", path, "-info", "-noout", "-passin", "fd:3")
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
		t.Fatalf("OpenSSL rejected generated PFX: %v", err)
	}
}
