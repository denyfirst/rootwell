package pfxinspect

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const testPassword = "R00twell-Inspect-fixture-93f2"

func fixture(t *testing.T) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(87), Subject: pkix.Name{CommonName: "pfx-inspect.example"}, DNSNames: []string{"pfx-inspect.example"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pkcs12.Modern2023.WithIterations(100_000).Encode(key, certificate, nil, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return data, certificate, key
}

func TestInspectModernPFXPublicOnly(t *testing.T) {
	data, certificate, _ := fixture(t)
	result, err := Inspect(data, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if result.MatchingCertificate.Subject != certificate.Subject.String() || len(result.Additional) != 0 {
		t.Fatalf("wrong public result: %+v", result)
	}
	if bytes.Contains([]byte(result.MatchingCertificate.Subject), []byte(testPassword)) {
		t.Fatal("password leaked into public result")
	}
}

func TestInspectRejectsWrongPasswordTamperAndUnsupported(t *testing.T) {
	data, _, _ := fixture(t)
	if _, err := Inspect(data, "wrong-password"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong password accepted: %v", err)
	}
	tampered := bytes.Clone(data)
	tampered[len(tampered)-8] ^= 0x01
	if _, err := Inspect(tampered, testPassword); err == nil {
		t.Fatal("tampered PFX accepted")
	}
	for _, input := range [][]byte{nil, data[:len(data)-1], append(bytes.Clone(data), 0), bytes.Repeat([]byte{0}, maxInputBytes+1)} {
		if _, err := Inspect(input, testPassword); err == nil {
			t.Fatal("malformed or oversized PFX accepted")
		}
	}
	if _, err := Inspect(data, ""); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("empty password accepted: %v", err)
	}
}

func TestPreflightRejectsExcessiveKDFBeforeDecode(t *testing.T) {
	data, _, _ := fixture(t)
	current, err := asn1.Marshal(100_000)
	if err != nil {
		t.Fatal(err)
	}
	excessive, err := asn1.Marshal(250_001)
	if err != nil || len(current) != len(excessive) {
		t.Fatal("test integer encoding changed")
	}
	if count := bytes.Count(data, current); count != 3 {
		t.Fatalf("expected three visible KDF work factors, got %d", count)
	}
	for position := 0; position < len(data); {
		relative := bytes.Index(data[position:], current)
		if relative < 0 {
			break
		}
		position += relative
		mutated := bytes.Clone(data)
		copy(mutated[position:position+len(current)], excessive)
		if err := Preflight(mutated); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("excessive KDF at offset %d accepted: %v", position, err)
		}
		if _, err := Inspect(mutated, testPassword); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("excessive KDF at offset %d reached decoder: %v", position, err)
		}
		position += len(current)
	}
}

func TestInspectRejectsMismatchedKeyAndDuplicateCertificate(t *testing.T) {
	_, certificate, key := fixture(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mismatched, err := pkcs12.Modern2023.WithIterations(100_000).Encode(otherKey, certificate, nil, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(mismatched, testPassword); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched key accepted: %v", err)
	}
	duplicate, err := pkcs12.Modern2023.WithIterations(100_000).Encode(key, certificate, []*x509.Certificate{certificate}, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(duplicate, testPassword); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate certificate accepted: %v", err)
	}
}

func TestInspectShowsAdditionalCertificateWithoutTrustClaim(t *testing.T) {
	_, certificate, key := fixture(t)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(88), Subject: pkix.Name{CommonName: "unverified-issuer.example"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, template, template, issuerKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pkcs12.Modern2023.WithIterations(100_000).Encode(key, certificate, []*x509.Certificate{issuer}, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Inspect(data, testPassword)
	if err != nil || len(result.Additional) != 1 || result.Additional[0].Subject != issuer.Subject.String() {
		t.Fatalf("additional certificate missing: %+v, %v", result, err)
	}
}

func TestInspectRejectsLegacyProfileWithoutFallback(t *testing.T) {
	_, certificate, key := fixture(t)
	legacy, err := pkcs12.LegacyDES.Encode(key, certificate, nil, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := Preflight(legacy); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("legacy profile reached password decoder: %v", err)
	}
	if _, err := Inspect(legacy, testPassword); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("legacy profile accepted: %v", err)
	}
}
