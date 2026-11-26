//go:build linux

package legacypemkey

import (
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// OpenSSL's "traditional" output is where these keys come from.
func TestDecryptOpensOpenSSLTraditionalKeys(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "password")
	if err := os.WriteFile(secret, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, commands := range map[string][][]string{
		"RSA, AES-256": {{"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "plain.pem"},
			{"rsa", "-in", "plain.pem", "-traditional", "-aes256", "-passout", "file:" + secret, "-out", "locked.pem"}},
		"EC, 3DES": {{"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "plain.pem"},
			{"ec", "-in", "plain.pem", "-des3", "-passout", "file:" + secret, "-out", "locked.pem"}},
	} {
		for _, args := range commands {
			command := exec.Command("openssl", args...)
			command.Dir = dir
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("%s: openssl %v: %v: %s", name, args, err, out)
			}
		}
		data, err := os.ReadFile(filepath.Join(dir, "locked.pem"))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(data)
		if block == nil || !IsEncrypted(block) {
			t.Fatalf("%s: OpenSSL did not write the legacy format", name)
		}
		der, err := Decrypt(block, []byte(password))
		if err != nil || len(der) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
		clear(der)
	}
}
