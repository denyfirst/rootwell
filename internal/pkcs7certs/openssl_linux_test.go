//go:build linux

package pkcs7certs

import (
	"bytes"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// OpenSSL's crl2pkcs7 writes the .p7b files most tools exchange.
func TestParseReadsOpenSSLBundles(t *testing.T) {
	certs := certificates(t, 2)
	dir := t.TempDir()
	chain := filepath.Join(dir, "chain.pem")
	var text []byte
	for _, der := range certs {
		text = append(text, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.WriteFile(chain, text, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "chain.p7b")
	if out, err := exec.Command("openssl", "crl2pkcs7", "-nocrl", "-certfile", chain, "-outform", "DER", "-out", output).CombinedOutput(); err != nil {
		t.Fatalf("openssl crl2pkcs7: %v: %s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil || len(got) != 2 {
		t.Fatalf("OpenSSL bundle was not read: %v", err)
	}
	for _, der := range certs {
		if !bytes.Equal(got[0], der) && !bytes.Equal(got[1], der) {
			t.Fatal("a certificate changed")
		}
	}
}
