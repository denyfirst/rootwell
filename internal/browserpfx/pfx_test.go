package browserpfx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/pfxinspect"
	"github.com/youmark/pkcs8"
)

const syntheticPassword = "synthetic-PFX-password-2026-9c42"
const syntheticOutputPassword = "different-synthetic-key-password-2026"

func fixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "synthetic.example"},
		DNSNames: []string{"synthetic.example"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return cert, private
}

func TestCreateInspectExtractAndRefuse(t *testing.T) {
	cert, key := fixture(t)
	defer clear(key)
	pfx, name, err := Create(cert, key, nil, []byte(syntheticPassword))
	if err != nil || !strings.HasSuffix(name, ".pfx") {
		t.Fatalf("create: %v", err)
	}
	defer clear(pfx)
	summary, err := Inspect(pfx, []byte(syntheticPassword))
	if err != nil || len(summary.Certificates) != 1 || !summary.Certificates[0].MatchingKey {
		t.Fatalf("inspect: %v, %+v", err, summary)
	}
	fingerprint := summary.Certificates[0].Fingerprint
	der, _, err := ExportCertificate(pfx, []byte(syntheticPassword), fingerprint, "der")
	if err != nil || !bytes.Equal(der, cert) {
		t.Fatalf("DER export: %v", err)
	}
	pemBytes, _, err := ExportCertificate(pfx, []byte(syntheticPassword), fingerprint, "pem")
	publicBlock, _ := pem.Decode(pemBytes)
	if err != nil || publicBlock == nil || !bytes.Equal(publicBlock.Bytes, cert) {
		t.Fatalf("PEM export: %v", err)
	}
	encrypted, _, err := ExportKey(pfx, []byte(syntheticPassword), fingerprint, []byte(syntheticOutputPassword))
	if err != nil || !bytes.HasPrefix(encrypted, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\n")) {
		t.Fatalf("key export: %v", err)
	}
	block, _ := pem.Decode(encrypted)
	decoded, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(syntheticOutputPassword))
	if err != nil || decoded == nil {
		t.Fatalf("encrypted output cannot be opened: %v", err)
	}
	clear(encrypted)
	wrong := []byte("wrong-password")
	if result, err := Inspect(pfx, wrong); err == nil || len(result.Certificates) != 0 {
		t.Fatal("wrong PFX password accepted")
	}
	if output, _, err := ExportCertificate(pfx, wrong, fingerprint, "pem"); err == nil || output != nil {
		t.Fatal("wrong password exported certificate")
	}
	if output, _, err := ExportKey(pfx, wrong, fingerprint, []byte(syntheticOutputPassword)); err == nil || output != nil {
		t.Fatal("wrong password exported key")
	}
	other := strings.Repeat("AA:", 31) + "AA"
	if other == fingerprint {
		t.Fatal("unexpected test fingerprint")
	}
	if output, _, err := ExportKey(pfx, []byte(syntheticPassword), other, []byte(syntheticOutputPassword)); err == nil || output != nil {
		t.Fatal("wrong fingerprint exported key")
	}
	if output, _, err := ExportCertificate(pfx, []byte(syntheticPassword), other, "pem"); err == nil || output != nil {
		t.Fatal("wrong fingerprint exported certificate")
	}
	if output, _, err := ExportCertificate(pfx, []byte(syntheticPassword), fingerprint, "crt"); err == nil || output != nil {
		t.Fatal("unsupported output format exported certificate")
	}
	if output, _, err := ExportKey(pfx, []byte(syntheticPassword), fingerprint, []byte(syntheticPassword)); err == nil || output != nil {
		t.Fatal("reused PFX password exported key")
	}
	if output, _, err := Create(cert, []byte("not a key"), nil, []byte(syntheticPassword)); err == nil || output != nil {
		t.Fatal("mismatched key accepted")
	}
	if output, _, err := Create(cert, key, nil, []byte("short")); err == nil || output != nil {
		t.Fatal("weak output password accepted")
	}
	tampered := bytes.Clone(pfx)
	tampered[len(tampered)-8] ^= 1
	if result, err := Inspect(tampered, []byte(syntheticPassword)); err == nil || len(result.Certificates) != 0 {
		t.Fatal("tampered PFX accepted")
	}
	if result, err := Inspect(append(bytes.Clone(pfx), 0), []byte(syntheticPassword)); err == nil || len(result.Certificates) != 0 {
		t.Fatal("PFX trailing data accepted")
	}
	if pfxinspect.Preflight(pfx) != nil {
		t.Fatal("created PFX failed preflight")
	}
}
