package browserexplore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCertificate(t testing.TB, serial int64, subject string) ([]byte, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func decode(t testing.TB, input []byte) Response {
	t.Helper()
	var response Response
	if err := json.Unmarshal([]byte(Process(input)), &response); err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != SchemaVersion {
		t.Fatalf("schema = %q", response.SchemaVersion)
	}
	return response
}

func TestProcessPublicCertificateAndBundle(t *testing.T) {
	firstDER, firstPEM := testCertificate(t, 1, "first.invalid")
	_, secondPEM := testCertificate(t, 2, "second.invalid")
	for _, test := range []struct {
		name     string
		input    []byte
		count    int
		encoding string
	}{
		{name: "single DER", input: firstDER, count: 1, encoding: "der"},
		{name: "single PEM", input: firstPEM, count: 1, encoding: "pem"},
		{name: "PEM bundle", input: append(bytes.Clone(firstPEM), secondPEM...), count: 2, encoding: "pem"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := decode(t, test.input)
			if !response.OK || response.Error != nil || response.Result == nil ||
				response.Result.Count != test.count || len(response.Result.Certificates) != test.count {
				t.Fatalf("response = %#v", response)
			}
			if response.Result.Verification != "not-performed" || response.Result.TrustAnchor != "not-selected" {
				t.Fatalf("exploration implied trust: %#v", response.Result)
			}
			first := response.Result.Certificates[0]
			if first.Encoding != test.encoding || first.Subject != "CN=first.invalid" ||
				first.Issuer != "CN=first.invalid" || first.SHA256 == "" ||
				first.NotBefore != "2026-01-01T00:00:00Z" || first.NotAfter != "2027-01-01T00:00:00Z" {
				t.Fatalf("certificate metadata = %#v", first)
			}
		})
	}
}

func TestProcessRejectsUnsafeInputWithoutEchoOrPartialOutput(t *testing.T) {
	_, certificate := testCertificate(t, 1, "first.invalid")
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-marker")})
	for _, test := range []struct {
		name  string
		input []byte
		code  ErrorCode
	}{
		{name: "empty", code: ErrorEmpty},
		{name: "secret only", input: private, code: ErrorUnexpectedContent},
		{name: "secret after certificate", input: append(bytes.Clone(certificate), private...), code: ErrorUnexpectedContent},
		{name: "duplicate", input: append(bytes.Clone(certificate), certificate...), code: ErrorDuplicate},
		{name: "malformed PEM", input: []byte("-----BEGIN CERTIFICATE-----\nmalformed-marker\n-----END CERTIFICATE-----"), code: ErrorUnexpectedContent},
		{name: "junk after certificate", input: append(bytes.Clone(certificate), []byte("trailing-marker")...), code: ErrorUnexpectedContent},
		{name: "oversized", input: make([]byte, 16<<20+1), code: ErrorTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded := Process(test.input)
			response := decode(t, test.input)
			if response.OK || response.Result != nil || response.Error == nil || response.Error.Code != test.code {
				t.Fatalf("response = %#v, want %q", response, test.code)
			}
			for _, marker := range []string{"secret-marker", "malformed-marker", "trailing-marker", "CN=first.invalid"} {
				if strings.Contains(encoded, marker) {
					t.Fatalf("failure echoed %q", marker)
				}
			}
		})
	}
}

func TestFailureResponseFailsClosed(t *testing.T) {
	var response Response
	if err := json.Unmarshal([]byte(FailureResponse(ErrorCode("unknown"))), &response); err != nil {
		t.Fatal(err)
	}
	if response.OK || response.Result != nil || response.Error == nil || response.Error.Code != ErrorInternal {
		t.Fatalf("response = %#v", response)
	}
}

func TestProcessEnforcesCertificateCountWithoutPartialResult(t *testing.T) {
	var bundle []byte
	for serial := int64(1); serial <= 65; serial++ {
		_, encoded := testCertificate(t, serial, "count.invalid")
		bundle = append(bundle, encoded...)
		if serial == 64 {
			response := decode(t, bundle)
			if !response.OK || response.Result == nil || response.Result.Count != 64 {
				t.Fatalf("64-certificate boundary = %#v", response)
			}
		}
	}
	response := decode(t, bundle)
	if response.OK || response.Result != nil || response.Error == nil || response.Error.Code != ErrorTooManyCertificates {
		t.Fatalf("65-certificate boundary = %#v", response)
	}
}

func FuzzProcessPublicBundleReturnsJSON(f *testing.F) {
	f.Add([]byte("not a certificate"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"))
	f.Fuzz(func(t *testing.T, input []byte) {
		encoded := Process(input)
		if len(encoded) > maxResponseBytes {
			t.Fatal("response exceeds browser limit")
		}
		var response Response
		if err := json.Unmarshal([]byte(encoded), &response); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if response.SchemaVersion != SchemaVersion || response.OK == (response.Error != nil) || response.OK == (response.Result == nil) {
			t.Fatalf("inconsistent response shape: %#v", response)
		}
		if response.OK && (response.Result.Count < 1 || response.Result.Count > 64 || response.Result.Count != len(response.Result.Certificates) || response.Result.Verification != "not-performed" || response.Result.TrustAnchor != "not-selected") {
			t.Fatalf("invalid success response: %#v", response.Result)
		}
	})
}
