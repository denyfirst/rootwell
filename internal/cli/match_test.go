package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseMatchArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		ok   bool
		json bool
	}{
		{name: "required flags", args: []string{"--cert", "cert.pem", "--key", "key.pem"}, ok: true},
		{name: "reordered with json", args: []string{"--key", "key.pem", "--json", "--cert", "cert.pem"}, ok: true, json: true},
		{name: "missing cert", args: []string{"--key", "key.pem"}},
		{name: "missing key", args: []string{"--cert", "cert.pem"}},
		{name: "duplicate cert", args: []string{"--cert", "one", "--cert", "two", "--key", "key"}},
		{name: "duplicate key", args: []string{"--cert", "cert", "--key", "one", "--key", "two"}},
		{name: "duplicate json", args: []string{"--json", "--json", "--cert", "cert", "--key", "key"}},
		{name: "unknown flag", args: []string{"--cert", "cert", "--key", "key", "--password", "secret"}},
		{name: "empty value", args: []string{"--cert", "", "--key", "key"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments, ok := parseMatchArguments(test.args)
			if ok != test.ok {
				t.Fatalf("parseMatchArguments() ok = %t, want %t", ok, test.ok)
			}
			if ok && arguments.jsonOutput != test.json {
				t.Fatalf("jsonOutput = %t, want %t", arguments.jsonOutput, test.json)
			}
		})
	}
}

func TestMatchCommand(t *testing.T) {
	certificate, privateKey, _ := cliMatchMaterial(t)
	certificatePath := t.TempDir() + "/certificate.pem"
	privateKeyPath := t.TempDir() + "/private-key.pem"
	writeMatchFixture(t, certificatePath, certificate)
	writeMatchFixture(t, privateKeyPath, privateKey)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"match", "--cert", certificatePath, "--key", privateKeyPath}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() code = %d, want %d; stderr = %q", code, ExitOK, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	for _, expected := range []string{
		"match: true\n",
		"certificate-encoding: pem\n",
		"private-key-encoding: pkcs8-pem\n",
		"private-key-public-algorithm: Ed25519\n",
		"algorithm-policy: not-evaluated\n",
		"certificate-trust: not-evaluated\n",
		"network: disabled\n",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("stdout does not contain %q: %q", expected, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), certificatePath) || strings.Contains(stdout.String(), privateKeyPath) {
		t.Fatalf("output exposed an input path: %q", stdout.String())
	}
}

func TestMatchJSONCommand(t *testing.T) {
	certificate, privateKey, _ := cliMatchMaterial(t)
	directory := t.TempDir()
	certificatePath := directory + "/certificate.data"
	privateKeyPath := directory + "/private-key.data"
	writeMatchFixture(t, certificatePath, certificate)
	writeMatchFixture(t, privateKeyPath, privateKey)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"match", "--json", "--cert", certificatePath, "--key", privateKeyPath}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() code = %d, want %d; stderr = %q", code, ExitOK, stderr.String())
	}
	var document matchJSONDocument
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if document.SchemaVersion != matchJSONSchema || !document.Match {
		t.Fatalf("unexpected match document: %#v", document)
	}
	if document.PrivateKey.Encoding != "pkcs8-pem" || document.PrivateKey.PublicKeySHA256 == "" {
		t.Fatalf("private-key public metadata missing: %#v", document.PrivateKey)
	}
	output := stdout.String()
	for _, forbidden := range []string{certificatePath, privateKeyPath, "private_key_bytes", "private_key_pem", "passphrase"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("JSON output contains forbidden value %q: %q", forbidden, output)
		}
	}
}

func TestMatchMismatchIsObservableFailure(t *testing.T) {
	certificate, _, _ := cliMatchMaterial(t)
	_, otherPrivateKey, _ := cliMatchMaterial(t)
	directory := t.TempDir()
	certificatePath := directory + "/certificate.pem"
	privateKeyPath := directory + "/different-key.pem"
	writeMatchFixture(t, certificatePath, certificate)
	writeMatchFixture(t, privateKeyPath, otherPrivateKey)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"match", "--cert", certificatePath, "--key", privateKeyPath}, &stdout, &stderr)
	if code != ExitFailure {
		t.Fatalf("Run() code = %d, want %d", code, ExitFailure)
	}
	if !strings.HasPrefix(stdout.String(), "match: false\n") {
		t.Fatalf("stdout = %q, want an explicit false verdict", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty for a completed mismatch verdict", stderr.String())
	}
}

func TestMatchJSONMismatchExitsOne(t *testing.T) {
	certificate, _, _ := cliMatchMaterial(t)
	_, otherPrivateKey, _ := cliMatchMaterial(t)
	directory := t.TempDir()
	certificatePath := directory + "/certificate.pem"
	privateKeyPath := directory + "/different-key.pem"
	writeMatchFixture(t, certificatePath, certificate)
	writeMatchFixture(t, privateKeyPath, otherPrivateKey)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"match", "--json", "--cert", certificatePath, "--key", privateKeyPath}, &stdout, &stderr)
	if code != ExitFailure {
		t.Fatalf("Run() code = %d, want %d", code, ExitFailure)
	}
	var document matchJSONDocument
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("invalid JSON mismatch output: %v", err)
	}
	if document.Match || document.SchemaVersion != matchJSONSchema || stderr.Len() != 0 {
		t.Fatalf("unexpected JSON mismatch result: %#v, stderr %q", document, stderr.String())
	}
}

func TestMatchRejectsEncryptedKeyWithoutEcho(t *testing.T) {
	certificate, _, _ := cliMatchMaterial(t)
	directory := t.TempDir()
	certificatePath := directory + "/certificate.pem"
	privateKeyPath := directory + "/customer-secret-name.key"
	writeMatchFixture(t, certificatePath, certificate)
	writeMatchFixture(t, privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("sensitive-private-input")}))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"match", "--cert", certificatePath, "--key", privateKeyPath}, &stdout, &stderr)
	if code != ExitFailure {
		t.Fatalf("Run() code = %d, want %d", code, ExitFailure)
	}
	if got := stderr.String(); got != "encrypted private keys are not supported in this version\n" {
		t.Fatalf("stderr = %q", got)
	}
	combined := stdout.String() + stderr.String()
	for _, secret := range []string{"customer-secret-name", "sensitive-private-input", privateKeyPath} {
		if strings.Contains(combined, secret) {
			t.Fatalf("output exposed %q: %q", secret, combined)
		}
	}
}

func TestMatchReadAndOutputFailures(t *testing.T) {
	certificate, privateKey, _ := cliMatchMaterial(t)
	directory := t.TempDir()
	certificatePath := directory + "/certificate.pem"
	privateKeyPath := directory + "/private-key.pem"
	writeMatchFixture(t, certificatePath, certificate)
	writeMatchFixture(t, privateKeyPath, privateKey)

	t.Run("missing key path is not echoed", func(t *testing.T) {
		secretPath := directory + "/tenant-secret-key.pem"
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := Run([]string{"match", "--cert", certificatePath, "--key", secretPath}, &stdout, &stderr); code != ExitFailure {
			t.Fatalf("Run() code = %d, want %d", code, ExitFailure)
		}
		if stderr.String() != "private key could not be read\n" || strings.Contains(stderr.String(), "tenant-secret") {
			t.Fatalf("unsafe diagnostic: %q", stderr.String())
		}
	})

	t.Run("output failure is operation failure", func(t *testing.T) {
		var stderr bytes.Buffer
		if code := Run([]string{"match", "--cert", certificatePath, "--key", privateKeyPath}, failingWriter{}, &stderr); code != ExitFailure {
			t.Fatalf("Run() code = %d, want %d", code, ExitFailure)
		}
		if stderr.String() != "output failed\n" {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})
}

func TestMatchArgumentErrorsDoNotEchoInput(t *testing.T) {
	const untrusted = "customer-password-super-secret"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"match", "--cert", "certificate.pem", "--key", "key.pem", "--password", untrusted}, &stdout, &stderr)
	if code != ExitUsage {
		t.Fatalf("Run() code = %d, want %d", code, ExitUsage)
	}
	if strings.Contains(stdout.String()+stderr.String(), untrusted) {
		t.Fatal("usage diagnostic reflected an untrusted argument")
	}
}

func cliMatchMaterial(t testing.TB) (certificatePEM, privateKeyPEM []byte, privateKey ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2026),
		Subject:      pkix.Name{CommonName: "match.rootwell.invalid"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), privateKey
}

func writeMatchFixture(t testing.TB, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}
