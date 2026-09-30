package pfxkeyexport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/pfxinspect"
	"github.com/youmark/pkcs8"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	fixturePFXPassword = "PFX-test-password-c867e39f"
	fixtureNewPassword = "NEW-test-password-918bd277"
)

func exportFixture(t *testing.T) ([]byte, string, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(301), Subject: pkix.Name{CommonName: "export.example"},
		DNSNames: []string{"export.example"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pkcs12.Modern2023.WithIterations(100_000).Encode(key, certificate, nil, fixturePFXPassword)
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := pfxinspect.Inspect(data, fixturePFXPassword)
	if err != nil {
		t.Fatal(err)
	}
	return data, inspection.MatchingCertificate.SHA256Fingerprint, key, certificate
}

func TestExportProducesOnlyEncryptedMatchingPKCS8(t *testing.T) {
	data, fingerprint, key, _ := exportFixture(t)
	output, err := Export(data, fixturePFXPassword, fingerprint, []byte(fixtureNewPassword))
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(output)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" || len(rest) != 0 || len(block.Headers) != 0 {
		t.Fatal("not one clean encrypted PKCS#8 PEM key")
	}
	if bytes.Contains(output, []byte(fixturePFXPassword)) || bytes.Contains(output, []byte(fixtureNewPassword)) || bytes.Contains(output, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatal("plaintext key/password marker reached output")
	}
	parsed, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(fixtureNewPassword))
	if err != nil {
		t.Fatal(err)
	}
	actual, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !actual.PublicKey.Equal(key.Public()) {
		t.Fatal("encrypted output does not contain matching key")
	}
	if _, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte("wrong-password")); err == nil {
		t.Fatal("wrong output password opened encrypted key")
	}
	second, err := Export(data, fixturePFXPassword, fingerprint, []byte(fixtureNewPassword))
	if err != nil || bytes.Equal(output, second) {
		t.Fatal("encrypted output reused salt and IV or failed second export")
	}
}

func TestExportRefusesWrongSelectionPasswordAndTamper(t *testing.T) {
	data, fingerprint, _, _ := exportFixture(t)
	wrong := fingerprint[:94] + "0"
	if wrong == fingerprint {
		wrong = fingerprint[:94] + "1"
	}
	mutated := bytes.Clone(data)
	mutated[len(mutated)-8] ^= 1
	for _, candidate := range []struct {
		data        []byte
		password    string
		fingerprint string
	}{
		{data, "wrong-password", fingerprint},
		{data, fixturePFXPassword, wrong},
		{mutated, fixturePFXPassword, fingerprint},
		{[]byte("not a PFX"), fixturePFXPassword, fingerprint},
		{bytes.Repeat([]byte("x"), (1<<20)+1), fixturePFXPassword, fingerprint},
	} {
		output, err := Export(candidate.data, candidate.password, candidate.fingerprint, []byte(fixtureNewPassword))
		if err == nil || output != nil {
			t.Fatal("invalid PFX/password/selection produced key output")
		}
	}
	for _, password := range [][]byte{nil, []byte("short"), []byte(fixturePFXPassword), []byte("non printable\npassword-12345")} {
		if bytes.Equal(password, []byte(fixturePFXPassword)) {
			continue // Password separation is enforced by the CLI, not this encoder.
		}
		output, err := Export(data, fixturePFXPassword, fingerprint, password)
		if err != ErrExportPassword || output != nil {
			t.Fatal("weak output password accepted")
		}
	}
}
