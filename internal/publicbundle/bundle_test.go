package publicbundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/limits"
)

func testCertificate(t testing.TB, serial int64) ([]byte, []byte) {
	return testCertificateNamed(t, serial, "bundle.invalid")
}

func testCertificateNamed(t testing.TB, serial int64, name string) ([]byte, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(1_900_000_000, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestParsePublicCertificateAndBundle(t *testing.T) {
	firstDER, firstPEM := testCertificate(t, 1)
	_, secondPEM := testCertificate(t, 2)

	for _, test := range []struct {
		name     string
		input    []byte
		count    int
		encoding certinspect.Encoding
	}{
		{name: "single DER", input: firstDER, count: 1, encoding: certinspect.EncodingDER},
		{name: "single PEM", input: firstPEM, count: 1, encoding: certinspect.EncodingPEM},
		{name: "two PEM certificates", input: append(bytes.Clone(firstPEM), secondPEM...), count: 2, encoding: certinspect.EncodingPEM},
	} {
		t.Run(test.name, func(t *testing.T) {
			entries, err := Parse(test.input)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(entries) != test.count {
				t.Fatalf("count = %d, want %d", len(entries), test.count)
			}
			if entries[0].Inspection.Encoding != test.encoding || !bytes.Equal(entries[0].DER, firstDER) {
				t.Fatal("first certificate was not preserved")
			}
			if entries[0].Inspection.SHA256Fingerprint == "" {
				t.Fatal("missing certificate fingerprint")
			}
		})
	}

	input := bytes.Clone(firstDER)
	entries, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] ^= 0xff
	if !bytes.Equal(entries[0].DER, firstDER) {
		t.Fatal("returned public DER aliases caller input")
	}
}

func TestParsePublicBundleRejectsUnsafeContent(t *testing.T) {
	firstDER, firstPEM := testCertificate(t, 1)
	_, secondPEM := testCertificate(t, 2)
	privateBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret input")})
	headerBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: firstDER})
	for _, test := range []struct {
		name  string
		input []byte
		want  error
	}{
		{name: "empty", input: []byte(" \n"), want: ErrEmpty},
		{name: "junk prefix", input: append([]byte("junk\n"), firstPEM...), want: ErrInvalidCertificate},
		{name: "junk between", input: append(append(bytes.Clone(firstPEM), []byte("junk\n")...), secondPEM...), want: ErrUnexpectedContent},
		{name: "junk after", input: append(bytes.Clone(firstPEM), []byte("junk")...), want: ErrUnexpectedContent},
		{name: "secret block", input: privateBlock, want: ErrUnexpectedContent},
		{name: "secret after public", input: append(bytes.Clone(firstPEM), privateBlock...), want: ErrUnexpectedContent},
		{name: "PEM headers", input: headerBlock, want: ErrUnexpectedContent},
		{name: "duplicate", input: append(bytes.Clone(firstPEM), firstPEM...), want: ErrDuplicateCertificate},
		{name: "invalid DER", input: []byte{0x30, 0x80, 0x00}, want: ErrInvalidCertificate},
		{name: "trailing DER", input: append(bytes.Clone(firstDER), 0), want: ErrInvalidCertificate},
		{name: "malformed PEM", input: []byte("-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n"), want: ErrUnexpectedContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			entries, err := Parse(test.input)
			if !errors.Is(err, test.want) || entries != nil {
				t.Fatalf("Parse returned %d entries and error %v; want no entries and %v", len(entries), err, test.want)
			}
		})
	}
}

func TestParsePublicBundleEnforcesLimits(t *testing.T) {
	if _, err := Parse(bytes.Repeat([]byte{'x'}, int(limits.MaxInputBytes)+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized input error = %v", err)
	}
	var bundle []byte
	for serial := int64(1); serial <= limits.MaxCertificatesPerBundle+1; serial++ {
		_, encoded := testCertificate(t, serial)
		bundle = append(bundle, encoded...)
		if serial == limits.MaxCertificatesPerBundle {
			entries, err := Parse(bundle)
			if err != nil || len(entries) != limits.MaxCertificatesPerBundle {
				t.Fatalf("64-certificate boundary returned %d entries and %v", len(entries), err)
			}
		}
	}
	if _, err := Parse(bundle); !errors.Is(err, ErrTooManyCertificates) {
		t.Fatalf("65-certificate input error = %v", err)
	}
}

func TestParsePublicBundleEnforcesAggregateMetadataLimit(t *testing.T) {
	var bundle []byte
	for serial := int64(1); serial <= limits.MaxCertificatesPerBundle; serial++ {
		_, encoded := testCertificateNamed(t, serial, strings.Repeat("x", 20<<10))
		bundle = append(bundle, encoded...)
	}
	if _, err := Parse(bundle); !errors.Is(err, ErrMetadataLimit) {
		t.Fatalf("aggregate metadata error = %v", err)
	}
}

func FuzzParsePublicBundle(f *testing.F) {
	_, encoded := testCertificate(f, 1)
	f.Add(encoded)
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----"))
	f.Add([]byte("junk"))
	f.Fuzz(func(t *testing.T, input []byte) {
		entries, err := Parse(input)
		if err != nil {
			if entries != nil {
				t.Fatal("failure returned certificates")
			}
			return
		}
		if len(entries) < 1 || len(entries) > limits.MaxCertificatesPerBundle {
			t.Fatalf("accepted %d certificates", len(entries))
		}
		for _, entry := range entries {
			reparsed, parseErr := certinspect.Inspect(entry.DER)
			if parseErr != nil || reparsed.SHA256Fingerprint != entry.Inspection.SHA256Fingerprint {
				t.Fatal("invalid accepted entry")
			}
		}
	})
}
