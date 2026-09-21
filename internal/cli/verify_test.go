package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certverify"
)

func TestVerifyCommand(t *testing.T) {
	files := writeCLITestChain(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"verify", files.leaf,
		"--hostname", "service.example.test",
		"--intermediates", files.intermediate,
		"--trust-bundle", files.root,
	}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() code = %d, want %d; stderr = %q", code, ExitOK, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	for _, expected := range []string{
		"verification: passed\n",
		"profile: tls-server\n",
		"hostname: \"service.example.test\"\n",
		"chain-depth: 3\n",
		"revocation: not-checked\n",
		"network: disabled\n",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("stdout does not contain %q: %q", expected, stdout.String())
		}
	}
}

func TestVerifyArgumentContract(t *testing.T) {
	tests := [][]string{
		{"verify"},
		{"verify", "leaf.pem", "--trust-bundle", "roots.pem"},
		{"verify", "leaf.pem", "--hostname", "service.example.test"},
		{"verify", "leaf.pem", "--trust-bundle", "roots.pem", "--hostname"},
		{"verify", "leaf.pem", "--trust-bundle", "roots.pem", "--hostname", "service.example.test", "--hostname", "again.example.test"},
		{"verify", "leaf.pem", "--trust-bundle", "roots.pem", "--hostname", "service.example.test", "--unknown", "value"},
	}
	for _, args := range tests {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != ExitUsage {
			t.Fatalf("Run(%q) code = %d, want %d", args, code, ExitUsage)
		}
		if stdout.Len() != 0 || stderr.String() != "invalid arguments\n" {
			t.Fatalf("Run(%q) stdout = %q, stderr = %q", args, stdout.String(), stderr.String())
		}
	}
}

func TestVerifyDoesNotEchoSensitiveInput(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "customer-private-production.pem")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"verify", secretPath,
		"--trust-bundle", "customer-secret-root.pem",
		"--hostname", "internal.customer.example",
	}, &stdout, &stderr)
	if code != ExitFailure {
		t.Fatalf("Run() code = %d, want %d", code, ExitFailure)
	}
	combined := stdout.String() + stderr.String()
	for _, forbidden := range []string{secretPath, "customer", "private", "production", "internal"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("diagnostic exposed untrusted input %q: %q", forbidden, combined)
		}
	}
}

func TestHumanVerificationOutputEscapesText(t *testing.T) {
	output := renderVerification(certverify.Result{
		Hostname:    "host\n\x1b[31m\u202e.example",
		EvaluatedAt: time.Unix(0, 0),
		Chain: []certverify.CertificateSummary{{
			Subject:           "safe\n\x1b[31mred\u202eevil",
			Issuer:            "issuer\rname",
			SHA256Fingerprint: "AA:BB",
		}},
	})
	for _, forbidden := range []string{"\x1b", "\u202e", "safe\n\x1b", "issuer\rname"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains raw untrusted text %q: %q", forbidden, output)
		}
	}
	for _, expected := range []string{`\n`, `\x1b`, `\u202e`, `\r`} {
		if !strings.Contains(output, expected) {
			t.Errorf("output does not contain escaped sequence %q: %q", expected, output)
		}
	}
}

func FuzzHumanVerificationOutput(f *testing.F) {
	f.Add("service.example.test", "subject", "issuer")
	f.Add("host\n\x1b[31m", "\u202eevil", "issuer\rname")
	f.Fuzz(func(t *testing.T, hostname, subject, issuer string) {
		output := renderVerification(certverify.Result{
			Hostname:    hostname,
			EvaluatedAt: time.Unix(0, 0),
			Chain:       []certverify.CertificateSummary{{Subject: subject, Issuer: issuer}},
		})
		for _, value := range []byte(output) {
			if value != '\n' && (value < 0x20 || value > 0x7e) {
				t.Fatalf("output contains unsafe byte 0x%02x", value)
			}
		}
	})
}

type cliVerifyFiles struct {
	leaf         string
	root         string
	intermediate string
}

func writeCLITestChain(t testing.TB) cliVerifyFiles {
	t.Helper()
	directory := t.TempDir()
	rootKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x81}, ed25519.SeedSize))
	intermediateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x82}, ed25519.SeedSize))
	leafKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x83}, ed25519.SeedSize))
	notBefore := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Rootwell CLI Test Root"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	rootDER := cliCreateCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	rootCertificate := cliParseCertificate(t, rootDER)
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Rootwell CLI Test Intermediate"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	intermediateDER := cliCreateCertificate(t, intermediateTemplate, rootCertificate, intermediateKey.Public(), rootKey)
	intermediateCertificate := cliParseCertificate(t, intermediateDER)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "service.example.test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"service.example.test"},
	}
	leafDER := cliCreateCertificate(t, leafTemplate, intermediateCertificate, leafKey.Public(), intermediateKey)

	files := cliVerifyFiles{
		leaf:         filepath.Join(directory, "leaf.der"),
		root:         filepath.Join(directory, "roots.pem"),
		intermediate: filepath.Join(directory, "intermediates.pem"),
	}
	for path, content := range map[string][]byte{
		files.leaf:         leafDER,
		files.root:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		files.intermediate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER}),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func cliCreateCertificate(t testing.TB, template, parent *x509.Certificate, publicKey any, signer ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func cliParseCertificate(t testing.TB, der []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
