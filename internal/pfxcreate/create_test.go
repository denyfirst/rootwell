package pfxcreate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/pfxinspect"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const testPassword = "aGeneratedHighEntropyValue-2026-X7p9"

func testMaterial(t *testing.T) (leafDER, keyDER, intermediateDER, rootDER []byte) {
	t.Helper()
	now := time.Now().Add(-time.Hour)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err = x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"}, NotBefore: now, NotAfter: now.Add(12 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	intermediateDER, err = x509.CreateCertificate(rand.Reader, intermediateTemplate, root, intermediateKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "test.example"}, DNSNames: []string{"test.example"}, NotBefore: now, NotAfter: now.Add(6 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, leafKey.Public(), intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err = x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestCreatePFXMatchesKeyAndOrderedIssuer(t *testing.T) {
	leaf, key, intermediate, _ := testMaterial(t)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate})
	output, err := Create(leaf, key, chain, testPassword)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer clear(output)
	decodedKey, decodedLeaf, decodedIssuers, err := pkcs12.DecodeChain(output, testPassword)
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	defer keymatch.ClearParsedKey(decodedKey)
	if !bytes.Equal(decodedLeaf.Raw, leaf) || len(decodedIssuers) != 1 || !bytes.Equal(decodedIssuers[0].Raw, intermediate) {
		t.Fatal("PFX changed leaf or issuer")
	}
	if _, _, _, err := pkcs12.DecodeChain(output, "wrong-password-2026-abcdef"); err == nil {
		t.Fatal("PFX accepted a wrong password")
	}
	tampered := bytes.Clone(output)
	tampered[len(tampered)-1] ^= 1
	if _, _, _, err := pkcs12.DecodeChain(tampered, testPassword); err == nil {
		t.Fatal("PFX accepted tampering")
	}
}

func TestCreateRejectsMismatchAndUnsafeMaterial(t *testing.T) {
	leaf, key, intermediate, root := testMaterial(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := Create(leaf, otherDER, nil, testPassword); !errors.Is(err, keymatch.ErrKeyMismatch) || output != nil {
		t.Fatalf("mismatched key accepted: %v", err)
	}
	for _, badChain := range [][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}),
		append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate})...),
		[]byte("-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----"),
	} {
		if output, err := Create(leaf, key, badChain, testPassword); !errors.Is(err, ErrInvalidChain) || output != nil {
			t.Fatalf("bad chain accepted: %v", err)
		}
	}
	for _, password := range []string{"", "short", "contains space and enough length", "ünicode-password-very-long"} {
		if output, err := Create(leaf, key, nil, password); !errors.Is(err, ErrInvalidPassword) || output != nil {
			t.Fatalf("bad password accepted: %v", err)
		}
	}
	if output, err := Create(append(bytes.Clone(leaf), 0), key, nil, testPassword); !errors.Is(err, ErrInvalidInput) || output != nil {
		t.Fatalf("trailing certificate accepted: %v", err)
	}
}

func TestCreateRefusesWeakRSACertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "weak.example"}, NotBefore: now, NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := Create(certificate, encodedKey, nil, testPassword); !errors.Is(err, ErrInvalidInput) || output != nil {
		t.Fatalf("weak RSA key accepted: %v", err)
	}
}

func TestPFXParsedKeyBoundaryRefusesInvalidKeys(t *testing.T) {
	leaf, _, _, _ := testMaterial(t)
	for _, key := range []any{nil, (*rsa.PrivateKey)(nil), (*ecdsa.PrivateKey)(nil), &rsa.PrivateKey{}, &ecdsa.PrivateKey{}, "unsupported"} {
		output, err := CreateWithParsedKey(leaf, key, nil, testPassword)
		if !errors.Is(err, ErrInvalidInput) || output != nil {
			clear(output)
			t.Fatal("invalid parsed key was accepted")
		}
	}
}

// The older Windows profile is 3DES under a SHA-1 MAC with 2048 iterations,
// and Rootwell reads it back; the default stays AES-256.
func TestCreateOlderWindowsProfileIs3DESAndReadable(t *testing.T) {
	leaf, keyDER, intermediate, _ := testMaterial(t)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate})
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	defer keymatch.ClearParsedKey(key)
	older, err := CreateWithParsedKeyProfile(leaf, key, chain, testPassword, OlderWindows)
	if err != nil {
		t.Fatal(err)
	}
	modern, err := CreateWithParsedKeyProfile(leaf, key, chain, testPassword, Modern)
	if err != nil {
		t.Fatal(err)
	}
	sha1MAC := []byte{0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a}
	tripleDES := []byte{0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03}
	aes256 := []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a}
	iterations := []byte{0x02, 0x02, 0x08, 0x00}
	if bytes.Count(older, tripleDES) != 2 || !bytes.Contains(older, sha1MAC) || bytes.Count(older, iterations) != 3 || bytes.Contains(older, aes256) {
		t.Fatal("the older Windows profile is not 3DES under a SHA-1 MAC with 2048 iterations")
	}
	if bytes.Contains(modern, tripleDES) || bytes.Count(modern, aes256) != 2 {
		t.Fatal("the default profile is not AES-256")
	}
	result, err := pfxinspect.Inspect(older, testPassword)
	if err != nil || len(result.Additional) != 1 {
		t.Fatalf("Rootwell cannot read its own older Windows PFX: %v", err)
	}
	if der, ok := result.CertificateDER(result.MatchingCertificate.SHA256Fingerprint); !ok || !bytes.Equal(der, leaf) {
		t.Fatal("the older Windows PFX holds another certificate")
	}
	if _, err := CreateWithParsedKeyProfile(leaf, key, chain, testPassword, Profile(7)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("an unknown profile was accepted: %v", err)
	}
	if _, err := CreateWithParsedKeyProfile(leaf, key, chain, "short", OlderWindows); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("the older profile accepted a weak password: %v", err)
	}
}
