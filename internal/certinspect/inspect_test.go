package certinspect

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/limits"
)

func TestInspectCertificate(t *testing.T) {
	der := testCertificateDER(t)
	digest := sha256.Sum256(der)

	tests := []struct {
		name     string
		input    []byte
		encoding Encoding
	}{
		{name: "DER", input: der, encoding: EncodingDER},
		{name: "PEM", input: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), encoding: EncodingPEM},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Inspect(test.input)
			if err != nil {
				t.Fatalf("Inspect() error = %v", err)
			}
			if result.Encoding != test.encoding {
				t.Errorf("Encoding = %q, want %q", result.Encoding, test.encoding)
			}
			if result.Subject != "CN=example.test,O=DenyFirst Test" {
				t.Errorf("Subject = %q", result.Subject)
			}
			if result.Issuer != result.Subject {
				t.Errorf("Issuer = %q, want subject", result.Issuer)
			}
			if result.Serial != "2A" {
				t.Errorf("Serial = %q, want 2A", result.Serial)
			}
			if result.SHA256Fingerprint != colonHex(digest[:]) {
				t.Errorf("SHA256Fingerprint = %q", result.SHA256Fingerprint)
			}
			if len(result.DNSNames) != 1 || result.DNSNames[0] != "example.test" {
				t.Errorf("DNSNames = %q", result.DNSNames)
			}
			if len(result.IPAddresses) != 1 || result.IPAddresses[0] != "192.0.2.10" {
				t.Errorf("IPAddresses = %q", result.IPAddresses)
			}
			if len(result.URIs) != 1 || result.URIs[0] != "spiffe://example.test/service" {
				t.Errorf("URIs = %q", result.URIs)
			}
			if result.IsCA {
				t.Error("IsCA = true, want false")
			}
		})
	}
}

func TestInspectRejectsTrailingData(t *testing.T) {
	der := testCertificateDER(t)
	pemCertificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "DER byte", input: append(append([]byte(nil), der...), 0)},
		{name: "PEM text", input: append(append([]byte(nil), pemCertificate...), []byte("unexpected")...)},
		{name: "second PEM object", input: append(append([]byte(nil), pemCertificate...), pemCertificate...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Inspect(test.input)
			if !errors.Is(err, ErrTrailingData) {
				t.Fatalf("Inspect() error = %v, want ErrTrailingData", err)
			}
		})
	}
}

func TestInspectRejectsMalformedOrUnsupportedInput(t *testing.T) {
	der := testCertificateDER(t)
	tests := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{name: "empty", wantErr: ErrEmpty},
		{name: "whitespace", input: []byte(" \r\n\t"), wantErr: ErrEmpty},
		{name: "random", input: []byte("not a certificate"), wantErr: ErrInvalidCertificate},
		{name: "truncated DER", input: der[:len(der)-1], wantErr: ErrInvalidCertificate},
		{name: "private key PEM", input: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), wantErr: ErrUnsupportedFormat},
		{name: "PEM header", input: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Unsafe": "value"}, Bytes: der}), wantErr: ErrInvalidCertificate},
		{name: "junk before PEM", input: append([]byte("junk\n"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...), wantErr: ErrInvalidCertificate},
		{name: "oversized", input: bytes.Repeat([]byte{'x'}, int(limits.MaxInputBytes)+1), wantErr: ErrTooLarge},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Inspect(test.input)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Inspect() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestCertificateMetadataLimits(t *testing.T) {
	tests := []struct {
		name        string
		certificate *x509.Certificate
	}{
		{
			name: "text amplification",
			certificate: &x509.Certificate{
				Subject: pkix.Name{CommonName: strings.Repeat("x", limits.MaxMetadataTextBytes+1)},
			},
		},
		{
			name: "repeated values",
			certificate: &x509.Certificate{
				DNSNames: make([]string, limits.MaxMetadataValues+1),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := resultFromCertificate(test.certificate, EncodingDER)
			if !errors.Is(err, ErrResourceLimit) {
				t.Fatalf("resultFromCertificate() error = %v, want ErrResourceLimit", err)
			}
		})
	}
}

func FuzzInspectCertificate(f *testing.F) {
	der := testCertificateDER(f)
	f.Add(der)
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	f.Add([]byte("not a certificate"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		result, err := Inspect(input)
		if err != nil {
			return
		}
		if result.Encoding != EncodingDER && result.Encoding != EncodingPEM {
			t.Fatalf("successful parse returned unknown encoding %q", result.Encoding)
		}
		if result.SHA256Fingerprint == "" {
			t.Fatal("successful parse returned an empty fingerprint")
		}
	})
}

func testCertificateDER(t testing.TB) []byte {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	identifier, err := url.Parse("spiffe://example.test/service")
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   "example.test",
			Organization: []string{"DenyFirst Test"},
		},
		NotBefore:             time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2026, 12, 20, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.test"},
		EmailAddresses:        []string{"security@example.test"},
		IPAddresses:           []net.IP{net.ParseIP("192.0.2.10")},
		URIs:                  []*url.URL{identifier},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
