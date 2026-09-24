package browserexport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"regexp"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/publicbundle"
)

func certificate(t testing.TB, serial int64) ([]byte, []byte, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "export.invalid"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	entries, err := publicbundle.Parse(encoded)
	if err != nil || len(entries) != 1 {
		t.Fatalf("fixture: %v", err)
	}
	return der, encoded, entries[0].Inspection.SHA256Fingerprint
}

func TestPrepareExportsOnlySelectedCertificate(t *testing.T) {
	_, firstPEM, firstFingerprint := certificate(t, 1)
	secondDER, secondPEM, secondFingerprint := certificate(t, 2)
	bundle := append(bytes.Clone(firstPEM), secondPEM...)
	originalBundle := bytes.Clone(bundle)
	if firstFingerprint == secondFingerprint {
		t.Fatal("fixtures must differ")
	}
	for _, format := range []string{"pem", "der"} {
		t.Run(format, func(t *testing.T) {
			result, code := Prepare(bundle, secondFingerprint, format)
			if code != "" || result.Fingerprint != secondFingerprint || result.Encoding != format {
				t.Fatalf("Prepare = %#v, %q", result, code)
			}
			defer clear(result.Bytes)
			if !regexp.MustCompile(`^rootwell-public-[0-9a-f]{16}-[0-9a-f]{32}\.` + format + `$`).MatchString(result.Filename) {
				t.Fatalf("unsafe filename %q", result.Filename)
			}
			parsed, err := publicbundle.Parse(result.Bytes)
			if err != nil || len(parsed) != 1 || !bytes.Equal(parsed[0].DER, secondDER) {
				t.Fatalf("export is not the selected certificate: %v", err)
			}
			if format == "pem" && !bytes.HasPrefix(result.Bytes, []byte("-----BEGIN CERTIFICATE-----\n")) {
				t.Fatal("PEM export is not a public certificate block")
			}
			if format == "der" && !bytes.Equal(result.Bytes, secondDER) {
				t.Fatal("DER export did not preserve original bytes")
			}
		})
	}
	first, code := Prepare(bundle, firstFingerprint, "pem")
	if code != "" {
		t.Fatal(code)
	}
	second, code := Prepare(bundle, firstFingerprint, "pem")
	if code != "" || first.Filename == second.Filename {
		t.Fatal("repeated exports reused a download name")
	}
	clear(first.Bytes)
	clear(second.Bytes)
	if !bytes.Equal(bundle, originalBundle) {
		t.Fatal("export modified source bytes")
	}
	fromDER, code := Prepare(secondDER, secondFingerprint, "pem")
	if code != "" || !bytes.HasPrefix(fromDER.Bytes, []byte("-----BEGIN CERTIFICATE-----\n")) {
		t.Fatalf("DER source export = %#v, %q", fromDER, code)
	}
	clear(fromDER.Bytes)
}

func TestPrepareRejectsChangedOrUnsafeSource(t *testing.T) {
	_, firstPEM, firstFingerprint := certificate(t, 1)
	_, secondPEM, secondFingerprint := certificate(t, 2)
	secret := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-marker")})
	for _, test := range []struct {
		name        string
		input       []byte
		fingerprint string
		format      string
		want        ErrorCode
	}{
		{name: "different certificate", input: secondPEM, fingerprint: firstFingerprint, format: "pem", want: ErrorNotFound},
		{name: "secret", input: secret, fingerprint: firstFingerprint, format: "pem", want: ErrorInvalidSource},
		{name: "mixed", input: append(bytes.Clone(firstPEM), secret...), fingerprint: firstFingerprint, format: "pem", want: ErrorInvalidSource},
		{name: "duplicate", input: append(bytes.Clone(firstPEM), firstPEM...), fingerprint: firstFingerprint, format: "pem", want: ErrorInvalidSource},
		{name: "malformed", input: []byte("invalid-certificate"), fingerprint: firstFingerprint, format: "pem", want: ErrorInvalidSource},
		{name: "oversized", input: make([]byte, 16<<20+1), fingerprint: firstFingerprint, format: "pem", want: ErrorTooLarge},
		{name: "invalid format", input: firstPEM, fingerprint: firstFingerprint, format: "pfx", want: ErrorInvalidRequest},
		{name: "invalid fingerprint", input: firstPEM, fingerprint: "../../secret", format: "pem", want: ErrorInvalidRequest},
		{name: "lowercase fingerprint", input: firstPEM, fingerprint: secondFingerprint[:1] + "g" + secondFingerprint[2:], format: "pem", want: ErrorInvalidRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, code := Prepare(test.input, test.fingerprint, test.format)
			if code != test.want || result.Filename != "" || len(result.Bytes) != 0 {
				t.Fatalf("Prepare = %#v, %q; want no output and %q", result, code, test.want)
			}
		})
	}
}

func FuzzPrepareNeverReturnsUnselectedCertificate(f *testing.F) {
	_, encoded, fingerprint := certificate(f, 1)
	f.Add(encoded)
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"))
	f.Fuzz(func(t *testing.T, input []byte) {
		result, code := Prepare(input, fingerprint, "der")
		if code != "" {
			if result.Filename != "" || len(result.Bytes) != 0 {
				t.Fatal("failure returned a partial export")
			}
			return
		}
		defer clear(result.Bytes)
		parsed, err := publicbundle.Parse(result.Bytes)
		if err != nil || len(parsed) != 1 || parsed[0].Inspection.SHA256Fingerprint != fingerprint {
			t.Fatalf("exported unselected certificate: %v", err)
		}
	})
}
