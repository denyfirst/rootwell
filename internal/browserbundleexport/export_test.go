package browserbundleexport

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

func certificate(t testing.TB, serial int64) ([]byte, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "bundle.invalid"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	entries, err := publicbundle.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, entries[0].Inspection.SHA256Fingerprint
}

func TestPrepareExportsExplicitOrderedSubset(t *testing.T) {
	first, firstFP := certificate(t, 1)
	second, secondFP := certificate(t, 2)
	third, thirdFP := certificate(t, 3)
	inputs := [][]byte{first, append(bytes.Clone(second), third...)}
	original := bytes.Clone(inputs[1])
	result, code := Prepare(inputs, []string{firstFP, secondFP, thirdFP}, []string{firstFP, thirdFP})
	if code != "" || len(result.Fingerprints) != 2 || !regexp.MustCompile(`^rootwell-public-bundle-[0-9a-f]{32}\.pem$`).MatchString(result.Filename) {
		t.Fatalf("unexpected export: %#v %q", result, code)
	}
	defer clear(result.Bytes)
	parsed, err := publicbundle.Parse(result.Bytes)
	if err != nil || len(parsed) != 2 || parsed[0].Inspection.SHA256Fingerprint != firstFP || parsed[1].Inspection.SHA256Fingerprint != thirdFP {
		t.Fatalf("output mismatch: %v", err)
	}
	if !bytes.Equal(original, inputs[1]) {
		t.Fatal("source changed")
	}
	other, code := Prepare(inputs, []string{firstFP, secondFP, thirdFP}, []string{firstFP, thirdFP})
	if code != "" || other.Filename == result.Filename {
		t.Fatal("download name reused")
	}
	clear(other.Bytes)
}

func TestPrepareRejectsChangedUnsafeAndUnselectedInput(t *testing.T) {
	first, firstFP := certificate(t, 1)
	second, secondFP := certificate(t, 2)
	secret := []byte("-----BEGIN PRIVATE KEY-----\nsecret-marker\n-----END PRIVATE KEY-----")
	for _, test := range []struct {
		name     string
		inputs   [][]byte
		expected []string
		selected []string
		want     ErrorCode
	}{
		{name: "changed", inputs: [][]byte{second}, expected: []string{firstFP}, selected: []string{firstFP}, want: ErrorChangedSource},
		{name: "secret", inputs: [][]byte{secret}, expected: []string{firstFP}, selected: []string{firstFP}, want: ErrorInvalidSource},
		{name: "mixed", inputs: [][]byte{append(bytes.Clone(first), secret...)}, expected: []string{firstFP}, selected: []string{firstFP}, want: ErrorInvalidSource},
		{name: "duplicate files", inputs: [][]byte{first, first}, expected: []string{firstFP, secondFP}, selected: []string{firstFP}, want: ErrorInvalidSource},
		{name: "empty selection", inputs: [][]byte{first}, expected: []string{firstFP}, want: ErrorInvalidRequest},
		{name: "unselected", inputs: [][]byte{first}, expected: []string{firstFP}, selected: []string{secondFP}, want: ErrorInvalidRequest},
		{name: "reverse order", inputs: [][]byte{append(bytes.Clone(first), second...)}, expected: []string{firstFP, secondFP}, selected: []string{secondFP, firstFP}, want: ErrorInvalidRequest},
		{name: "duplicate selection", inputs: [][]byte{first}, expected: []string{firstFP}, selected: []string{firstFP, firstFP}, want: ErrorInvalidRequest},
		{name: "invalid fingerprint", inputs: [][]byte{first}, expected: []string{"../../secret"}, selected: []string{firstFP}, want: ErrorInvalidRequest},
		{name: "too large", inputs: [][]byte{make([]byte, 16<<20+1)}, expected: []string{firstFP}, selected: []string{firstFP}, want: ErrorTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, code := Prepare(test.inputs, test.expected, test.selected)
			if code != test.want || result.Filename != "" || len(result.Bytes) != 0 {
				t.Fatalf("Prepare = %#v, %q, want %q", result, code, test.want)
			}
		})
	}
}

func FuzzPrepareBundleNeverExportsUnselectedCertificate(f *testing.F) {
	first, firstFP := certificate(f, 1)
	f.Add(first)
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"))
	f.Fuzz(func(t *testing.T, input []byte) {
		result, code := Prepare([][]byte{input}, []string{firstFP}, []string{firstFP})
		if code != "" {
			if len(result.Bytes) != 0 || result.Filename != "" {
				t.Fatal("failure returned output")
			}
			return
		}
		defer clear(result.Bytes)
		parsed, err := publicbundle.Parse(result.Bytes)
		if err != nil || len(parsed) != 1 || parsed[0].Inspection.SHA256Fingerprint != firstFP {
			t.Fatalf("unselected export: %v", err)
		}
	})
}
