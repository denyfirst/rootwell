package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certinspect"
)

func TestRunContract(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "missing command",
			wantCode:   ExitUsage,
			wantStderr: "command required\n",
		},
		{
			name:       "help",
			args:       []string{"help"},
			wantCode:   ExitOK,
			wantStdout: helpText,
		},
		{
			name:       "long help flag",
			args:       []string{"--help"},
			wantCode:   ExitOK,
			wantStdout: helpText,
		},
		{
			name:       "version",
			args:       []string{"version"},
			wantCode:   ExitOK,
			wantStdout: "rootwell development\n",
		},
		{
			name:       "unknown command",
			args:       []string{"unknown"},
			wantCode:   ExitUsage,
			wantStderr: "unknown command\n",
		},
		{
			name:       "extra argument",
			args:       []string{"help", "unexpected"},
			wantCode:   ExitUsage,
			wantStderr: "invalid arguments\n",
		},
		{
			name:       "inspect missing path",
			args:       []string{"inspect"},
			wantCode:   ExitUsage,
			wantStderr: "invalid arguments\n",
		},
		{
			name:       "inspect extra path",
			args:       []string{"inspect", "one", "two"},
			wantCode:   ExitUsage,
			wantStderr: "invalid arguments\n",
		},
		{
			name:       "inspect json missing path",
			args:       []string{"inspect", "--json"},
			wantCode:   ExitUsage,
			wantStderr: "invalid arguments\n",
		},
		{
			name:       "inspect unknown option",
			args:       []string{"inspect", "--yaml", "certificate.pem"},
			wantCode:   ExitUsage,
			wantStderr: "invalid arguments\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			gotCode := Run(test.args, &stdout, &stderr)
			if gotCode != test.wantCode {
				t.Fatalf("Run() code = %d, want %d", gotCode, test.wantCode)
			}
			if got := stdout.String(); got != test.wantStdout {
				t.Errorf("stdout = %q, want %q", got, test.wantStdout)
			}
			if got := stderr.String(); got != test.wantStderr {
				t.Errorf("stderr = %q, want %q", got, test.wantStderr)
			}
		})
	}
}

func TestInspectCommand(t *testing.T) {
	path := t.TempDir() + "/certificate.unknown-extension"
	if err := os.WriteFile(path, cliTestCertificateDER(t), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if got := Run([]string{"inspect", path}, &stdout, &stderr); got != ExitOK {
		t.Fatalf("Run() code = %d, want %d; stderr = %q", got, ExitOK, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	for _, expected := range []string{
		"type: x509-certificate\n",
		"encoding: der\n",
		"subject: \"CN=example.test\"\n",
		"serial: 2A\n",
		"sha256: ",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("stdout does not contain %q: %q", expected, stdout.String())
		}
	}
}

func TestInspectJSONCommand(t *testing.T) {
	path := t.TempDir() + "/certificate.data"
	if err := os.WriteFile(path, cliTestCertificateDER(t), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if got := Run([]string{"inspect", "--json", path}, &stdout, &stderr); got != ExitOK {
		t.Fatalf("Run() code = %d, want %d; stderr = %q", got, ExitOK, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	var document inspectJSON
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("JSON output is invalid: %v", err)
	}
	if document.SchemaVersion != "rootwell.inspect.x509.v1" {
		t.Errorf("schema_version = %q, want rootwell.inspect.x509.v1", document.SchemaVersion)
	}
	if document.ObjectType != "x509-certificate" || document.Encoding != "der" {
		t.Errorf("unexpected object identity: %#v", document)
	}
	if document.Subject != "CN=example.test" || document.Serial != "2A" {
		t.Errorf("unexpected certificate identity: %#v", document)
	}
	if document.PublicKey.Algorithm != "Ed25519" || document.PublicKey.Bits != 256 {
		t.Errorf("unexpected public key: %#v", document.PublicKey)
	}
	if document.Fingerprints.SHA256 == "" {
		t.Error("SHA-256 fingerprint is empty")
	}
}

func TestJSONCertificateOutputIsASCIIAndSemantic(t *testing.T) {
	result := certinspect.Result{
		Encoding:           certinspect.EncodingPEM,
		Subject:            "şəxs\u202e😀\x7fname",
		Issuer:             "issuer",
		NotBefore:          time.Unix(0, 0),
		NotAfter:           time.Unix(1, 0),
		PublicKeyAlgorithm: "Ed25519",
		PublicKeyBits:      256,
		SignatureAlgorithm: "PureEd25519",
		DNSNames:           []string{"münasib.example"},
	}
	output, err := renderCertificateJSON(result)
	if err != nil {
		t.Fatalf("renderCertificateJSON() error = %v", err)
	}
	for _, value := range []byte(output) {
		if value != '\n' && (value < 0x20 || value > 0x7e) {
			t.Fatalf("JSON output contains unsafe byte 0x%02x", value)
		}
	}
	if !strings.Contains(output, `\u202e`) || !strings.Contains(output, `\ud83d\ude00`) {
		t.Fatalf("JSON output does not escape Unicode controls and supplementary runes: %q", output)
	}
	if !strings.Contains(output, `"key_usage": []`) {
		t.Fatalf("empty repeated fields must be arrays, not null: %q", output)
	}

	var decoded inspectJSON
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Fatalf("JSON output is invalid: %v", err)
	}
	if decoded.Subject != result.Subject || len(decoded.SubjectAlternativeNames.DNS) != 1 || decoded.SubjectAlternativeNames.DNS[0] != result.DNSNames[0] {
		t.Fatalf("ASCII escaping changed JSON semantics: %#v", decoded)
	}
}

func TestJSONCertificateOutputRejectsInvalidUTF8(t *testing.T) {
	_, err := renderCertificateJSON(certinspect.Result{Subject: string([]byte{0xff})})
	if !errors.Is(err, errInvalidJSONText) {
		t.Fatalf("renderCertificateJSON() error = %v, want errInvalidJSONText", err)
	}
}

func TestJSONSchemaExcludesSecretBearingFields(t *testing.T) {
	var inspectType inspectJSON
	inspectStruct := reflect.TypeOf(inspectType)
	var visit func(reflect.Type)
	visit = func(valueType reflect.Type) {
		if valueType.Kind() == reflect.Pointer || valueType.Kind() == reflect.Slice || valueType.Kind() == reflect.Array {
			visit(valueType.Elem())
			return
		}
		if valueType.Kind() != reflect.Struct {
			return
		}
		for index := 0; index < valueType.NumField(); index++ {
			field := valueType.Field(index)
			tag := strings.ToLower(strings.Split(field.Tag.Get("json"), ",")[0])
			name := strings.ToLower(field.Name)
			if strings.Contains(name, "private") || strings.Contains(tag, "private") ||
				strings.Contains(name, "passphrase") || strings.Contains(tag, "passphrase") ||
				strings.Contains(name, "password") || strings.Contains(tag, "password") ||
				tag == "raw" || tag == "input" || tag == "path" || tag == "file_path" || tag == "input_path" || strings.HasSuffix(tag, "_bytes") {
				t.Errorf("JSON schema contains secret-bearing field %q", tag)
			}
			visit(field.Type)
		}
	}
	visit(inspectStruct)
}

func TestInspectDoesNotEchoPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "missing file", path: t.TempDir() + "/customer-secret-key.pem"},
		{name: "invalid content", path: t.TempDir() + "/customer-private-hostname.pem"},
	}
	if err := os.WriteFile(tests[1].path, []byte("customer private material"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if got := Run([]string{"inspect", test.path}, &stdout, &stderr); got != ExitFailure {
				t.Fatalf("Run() code = %d, want %d", got, ExitFailure)
			}
			combined := stdout.String() + stderr.String()
			for _, forbidden := range []string{test.path, "customer", "private", "material"} {
				if strings.Contains(combined, forbidden) {
					t.Fatalf("diagnostic exposed untrusted input %q: %q", forbidden, combined)
				}
			}
		})
	}
}

func TestHumanCertificateOutputEscapesText(t *testing.T) {
	result := certinspect.Result{
		Encoding:           certinspect.EncodingPEM,
		Subject:            "safe\n\x1b[31mred\u202eevil",
		Issuer:             "issuer\rname",
		Serial:             "2A",
		NotBefore:          time.Unix(0, 0),
		NotAfter:           time.Unix(1, 0),
		PublicKeyAlgorithm: "Ed25519",
		SignatureAlgorithm: "PureEd25519",
		SHA256Fingerprint:  "AA:BB",
		DNSNames:           []string{"host\tname"},
		EmailAddresses:     []string{"security\n@example.test"},
		IPAddresses:        []string{"192.0.2.10"},
		URIs:               []string{"spiffe://example/\x1b]0;title"},
	}

	output := renderCertificate(result)
	for _, forbidden := range []string{"\x1b", "\u202e", "safe\n\x1b", "issuer\rname", "host\tname"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains raw untrusted text %q: %q", forbidden, output)
		}
	}
	for _, expected := range []string{`\n`, `\x1b`, `\u202e`, `\r`, `\t`} {
		if !strings.Contains(output, expected) {
			t.Errorf("output does not contain escaped sequence %q: %q", expected, output)
		}
	}
}

func TestUnknownCommandDoesNotEchoInput(t *testing.T) {
	const secret = "\x1b[31m/private/customer/secret-key.pem"
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if got := Run([]string{secret}, &stdout, &stderr); got != ExitUsage {
		t.Fatalf("Run() code = %d, want %d", got, ExitUsage)
	}

	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, secret) || strings.Contains(combined, "customer") {
		t.Fatalf("diagnostic reflected untrusted input: %q", combined)
	}
}

func TestRunReportsWriteFailure(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		stdout io.Writer
		stderr io.Writer
	}{
		{
			name:   "requested output fails",
			args:   []string{"help"},
			stdout: failingWriter{},
			stderr: io.Discard,
		},
		{
			name:   "diagnostic output fails",
			stdout: io.Discard,
			stderr: failingWriter{},
		},
		{
			name:   "requested output is short",
			args:   []string{"help"},
			stdout: shortWriter{},
			stderr: io.Discard,
		},
		{
			name:   "diagnostic output is short",
			stdout: io.Discard,
			stderr: shortWriter{},
		},
		{
			name:   "nil stdout",
			args:   []string{"version"},
			stdout: nil,
			stderr: io.Discard,
		},
		{
			name:   "nil stderr",
			args:   []string{"help"},
			stdout: io.Discard,
			stderr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Run(test.args, test.stdout, test.stderr); got != ExitFailure {
				t.Fatalf("Run() code = %d, want %d", got, ExitFailure)
			}
		})
	}
}

func FuzzRun(f *testing.F) {
	f.Add("")
	f.Add("inspect")
	f.Add("\x00\x1b[31m")
	f.Add("/private/customer/key.pem")

	f.Fuzz(func(t *testing.T, input string) {
		digest := sha256.Sum256([]byte(input))
		untrusted := "untrusted-" + hex.EncodeToString(digest[:])

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if got := Run([]string{untrusted}, &stdout, &stderr); got != ExitUsage {
			t.Fatalf("Run() code = %d, want %d", got, ExitUsage)
		}

		combined := stdout.String() + stderr.String()
		if strings.Contains(combined, untrusted) {
			t.Fatalf("diagnostic reflected untrusted input: %q", combined)
		}
	})
}

func FuzzHumanCertificateOutput(f *testing.F) {
	f.Add("subject", "issuer", "example.test")
	f.Add("\x1b[31m", "line\nfeed", "\u202eevil")

	f.Fuzz(func(t *testing.T, subject, issuer, name string) {
		output := renderCertificate(certinspect.Result{
			Encoding:           certinspect.EncodingDER,
			Subject:            subject,
			Issuer:             issuer,
			PublicKeyAlgorithm: "Ed25519",
			SignatureAlgorithm: "PureEd25519",
			DNSNames:           []string{name},
		})
		for _, value := range []byte(output) {
			if value != '\n' && (value < 0x20 || value > 0x7e) {
				t.Fatalf("output contains unsafe byte 0x%02x", value)
			}
		}
	})
}

func FuzzJSONCertificateOutput(f *testing.F) {
	f.Add("subject", "issuer", "example.test")
	f.Add("şəxs\u202e😀\x7f", "line\nfeed", "münasib.example")

	f.Fuzz(func(t *testing.T, subject, issuer, name string) {
		output, err := renderCertificateJSON(certinspect.Result{
			Encoding: certinspect.EncodingDER,
			Subject:  subject,
			Issuer:   issuer,
			DNSNames: []string{name},
		})
		validText := strings.ToValidUTF8(subject, "\uFFFD") == subject && strings.ToValidUTF8(issuer, "\uFFFD") == issuer && strings.ToValidUTF8(name, "\uFFFD") == name
		if !validText {
			if !errors.Is(err, errInvalidJSONText) {
				t.Fatalf("invalid UTF-8 error = %v, want errInvalidJSONText", err)
			}
			return
		}
		if err != nil {
			t.Fatalf("renderCertificateJSON() error = %v", err)
		}
		for _, value := range []byte(output) {
			if value != '\n' && (value < 0x20 || value > 0x7e) {
				t.Fatalf("JSON output contains unsafe byte 0x%02x", value)
			}
		}
		var decoded inspectJSON
		if err := json.Unmarshal([]byte(output), &decoded); err != nil {
			t.Fatalf("JSON output is invalid: %v", err)
		}
		if decoded.Subject != subject || decoded.Issuer != issuer || len(decoded.SubjectAlternativeNames.DNS) != 1 || decoded.SubjectAlternativeNames.DNS[0] != name {
			t.Fatal("JSON escaping changed certificate metadata")
		}
	})
}

func cliTestCertificateDER(t testing.TB) []byte {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "example.test"},
		NotBefore:    time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 12, 20, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

type shortWriter struct{}

func (shortWriter) Write(value []byte) (int, error) {
	return len(value) - 1, nil
}
