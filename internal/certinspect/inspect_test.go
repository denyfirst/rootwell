package certinspect

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
			if !result.BasicConstraintsValid {
				t.Error("BasicConstraintsValid = false, want true")
			}
			if result.PublicKeyBits != 256 {
				t.Errorf("PublicKeyBits = %d, want 256", result.PublicKeyBits)
			}
			if !equalStrings(result.KeyUsage, []string{"digital-signature"}) {
				t.Errorf("KeyUsage = %q", result.KeyUsage)
			}
			if !equalStrings(result.ExtendedKeyUsage, []string{"server-auth"}) {
				t.Errorf("ExtendedKeyUsage = %q", result.ExtendedKeyUsage)
			}
			if result.SubjectKeyID != "01:02:03:04" {
				t.Errorf("SubjectKeyID = %q", result.SubjectKeyID)
			}
		})
	}
}

func TestPublicKeyDetails(t *testing.T) {
	tests := []struct {
		name      string
		publicKey any
		wantBits  int
		wantCurve string
	}{
		{name: "RSA", publicKey: &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}, wantBits: 2048},
		{name: "ECDSA", publicKey: &ecdsa.PublicKey{Curve: elliptic.P256()}, wantBits: 256, wantCurve: "P-256"},
		{name: "Ed25519", publicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), wantBits: 256},
		{name: "unknown", publicKey: struct{}{}},
		{name: "nil RSA", publicKey: (*rsa.PublicKey)(nil)},
		{name: "nil ECDSA", publicKey: (*ecdsa.PublicKey)(nil)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bits, curve := publicKeyDetails(test.publicKey)
			if bits != test.wantBits || curve != test.wantCurve {
				t.Fatalf("publicKeyDetails() = (%d, %q), want (%d, %q)", bits, curve, test.wantBits, test.wantCurve)
			}
		})
	}
}

func TestUsageNamesAreStable(t *testing.T) {
	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly | x509.KeyUsage(1<<20)
	want := []string{
		"digital-signature", "content-commitment", "key-encipherment", "data-encipherment",
		"key-agreement", "certificate-signing", "crl-signing", "encipher-only", "decipher-only",
		"unknown-0x100000",
	}
	if got := keyUsageNames(usage); !equalStrings(got, want) {
		t.Fatalf("keyUsageNames() = %q, want %q", got, want)
	}

	extended := []struct {
		usage x509.ExtKeyUsage
		name  string
	}{
		{x509.ExtKeyUsageAny, "any"},
		{x509.ExtKeyUsageServerAuth, "server-auth"},
		{x509.ExtKeyUsageClientAuth, "client-auth"},
		{x509.ExtKeyUsageCodeSigning, "code-signing"},
		{x509.ExtKeyUsageEmailProtection, "email-protection"},
		{x509.ExtKeyUsageIPSECEndSystem, "ipsec-end-system"},
		{x509.ExtKeyUsageIPSECTunnel, "ipsec-tunnel"},
		{x509.ExtKeyUsageIPSECUser, "ipsec-user"},
		{x509.ExtKeyUsageTimeStamping, "time-stamping"},
		{x509.ExtKeyUsageOCSPSigning, "ocsp-signing"},
		{x509.ExtKeyUsageMicrosoftServerGatedCrypto, "microsoft-server-gated-crypto"},
		{x509.ExtKeyUsageNetscapeServerGatedCrypto, "netscape-server-gated-crypto"},
		{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, "microsoft-commercial-code-signing"},
		{x509.ExtKeyUsageMicrosoftKernelCodeSigning, "microsoft-kernel-code-signing"},
		{x509.ExtKeyUsage(999), "unknown-999"},
	}
	for _, test := range extended {
		if got := extendedKeyUsageName(test.usage); got != test.name {
			t.Errorf("extendedKeyUsageName(%d) = %q, want %q", test.usage, got, test.name)
		}
	}
}

func TestBasicConstraintsPathLength(t *testing.T) {
	result, err := resultFromCertificate(&x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}, EncodingDER)
	if err != nil {
		t.Fatalf("resultFromCertificate() error = %v", err)
	}
	if result.MaxPathLength == nil || *result.MaxPathLength != 0 {
		t.Fatalf("MaxPathLength = %v, want explicit zero", result.MaxPathLength)
	}
}

func TestResultReportsExtensionsAndIdentifiers(t *testing.T) {
	result, err := resultFromCertificate(&x509.Certificate{
		SubjectKeyId:   []byte{0xaa, 0xbb},
		AuthorityKeyId: []byte{0xcc, 0xdd},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			{1, 2, 3, 4},
		},
		Extensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: false},
		},
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{1, 2, 3, 5}},
	}, EncodingDER)
	if err != nil {
		t.Fatalf("resultFromCertificate() error = %v", err)
	}
	if result.SubjectKeyID != "AA:BB" || result.AuthorityKeyID != "CC:DD" {
		t.Errorf("unexpected key identifiers: subject=%q authority=%q", result.SubjectKeyID, result.AuthorityKeyID)
	}
	if !equalStrings(result.ExtendedKeyUsage, []string{"server-auth", "client-auth"}) {
		t.Errorf("ExtendedKeyUsage = %q", result.ExtendedKeyUsage)
	}
	if !equalStrings(result.UnknownExtendedKeyUsage, []string{"1.2.3.4"}) {
		t.Errorf("UnknownExtendedKeyUsage = %q", result.UnknownExtendedKeyUsage)
	}
	if !equalStrings(result.CriticalExtensions, []string{"2.5.29.15"}) {
		t.Errorf("CriticalExtensions = %q", result.CriticalExtensions)
	}
	if !equalStrings(result.UnhandledCriticalExtensions, []string{"1.2.3.5"}) {
		t.Errorf("UnhandledCriticalExtensions = %q", result.UnhandledCriticalExtensions)
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
		{
			name: "serial amplification",
			certificate: &x509.Certificate{
				SerialNumber: new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, limits.MaxMetadataTextBytes/2+1)),
			},
		},
		{
			name: "key identifier amplification",
			certificate: &x509.Certificate{
				SubjectKeyId: bytes.Repeat([]byte{0xff}, limits.MaxMetadataTextBytes/3+1),
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
		SubjectKeyId:          []byte{1, 2, 3, 4},
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

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
