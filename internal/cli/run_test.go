package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"os"
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
