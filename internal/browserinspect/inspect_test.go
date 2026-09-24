package browserinspect

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

func TestProcessCertificate(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	var response Response
	if err := json.Unmarshal([]byte(Process(testCertificateDER(t), now)), &response); err != nil {
		t.Fatalf("Process() returned invalid JSON: %v", err)
	}
	if !response.OK || response.Error != nil || response.Result == nil {
		t.Fatalf("Process() response = %#v, want success", response)
	}
	if response.SchemaVersion != SchemaVersion || response.Result.SchemaVersion != "rootwell.inspect.x509.v1" {
		t.Fatalf("unexpected schema versions: %#v", response)
	}
	if response.Result.Subject != "CN=browser.rootwell.invalid" || response.Result.Encoding != "der" {
		t.Fatalf("unexpected certificate identity: %#v", response.Result)
	}
	if response.Result.TimeWindow.Status != "within-validity-window" {
		t.Fatalf("time-window status = %q", response.Result.TimeWindow.Status)
	}
}

func TestProcessClassifiesFailuresWithoutEchoingInput(t *testing.T) {
	testCases := []struct {
		name  string
		input []byte
		code  ErrorCode
	}{
		{name: "empty", code: ErrorEmpty},
		{name: "unsupported", input: []byte("-----BEGIN PRIVATE KEY-----\nsensitive-private-value\n-----END PRIVATE KEY-----"), code: ErrorUnsupportedEncoding},
		{name: "trailing", input: append(testCertificatePEM(t), []byte("attacker-controlled-trailer")...), code: ErrorTrailingData},
		{name: "invalid", input: []byte("not-a-certificate-sensitive-marker"), code: ErrorInvalidCertificate},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			output := Process(testCase.input, time.Unix(0, 0))
			var response Response
			if err := json.Unmarshal([]byte(output), &response); err != nil {
				t.Fatalf("Process() returned invalid JSON: %v", err)
			}
			if response.OK || response.Result != nil || response.Error == nil || response.Error.Code != testCase.code {
				t.Fatalf("Process() response = %#v, want %q failure", response, testCase.code)
			}
			for _, marker := range []string{"sensitive-private-value", "attacker-controlled-trailer", "not-a-certificate-sensitive-marker"} {
				if strings.Contains(output, marker) {
					t.Fatalf("failure response echoed input marker %q", marker)
				}
			}
		})
	}
}

func TestProcessRejectsOversizedInput(t *testing.T) {
	input := make([]byte, 16<<20+1)
	var response Response
	if err := json.Unmarshal([]byte(Process(input, time.Unix(0, 0))), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != ErrorTooLarge {
		t.Fatalf("Process() response = %#v, want input-too-large", response)
	}
}

func TestFailureResponseFailsClosedForUnknownCode(t *testing.T) {
	var response Response
	if err := json.Unmarshal([]byte(FailureResponse(ErrorCode("unexpected"))), &response); err != nil {
		t.Fatal(err)
	}
	if response.OK || response.Error == nil || response.Error.Code != ErrorInternal {
		t.Fatalf("FailureResponse() = %#v, want internal failure", response)
	}
}

func FuzzProcessReturnsJSON(f *testing.F) {
	f.Add([]byte("not a certificate"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"))
	f.Fuzz(func(t *testing.T, input []byte) {
		output := Process(input, time.Unix(0, 0))
		var response Response
		if err := json.Unmarshal([]byte(output), &response); err != nil {
			t.Fatalf("Process() returned invalid JSON: %v", err)
		}
		if response.SchemaVersion != SchemaVersion {
			t.Fatalf("schema_version = %q", response.SchemaVersion)
		}
		if response.OK == (response.Error != nil) || response.OK == (response.Result == nil) {
			t.Fatalf("inconsistent response shape: %#v", response)
		}
	})
}

func testCertificateDER(t testing.TB) []byte {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(20260924),
		Subject:      pkix.Name{CommonName: "browser.rootwell.invalid"},
		DNSNames:     []string{"browser.rootwell.invalid", "api.rootwell.invalid"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func testCertificatePEM(t testing.TB) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCertificateDER(t)})
}
