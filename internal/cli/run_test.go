package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
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

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

type shortWriter struct{}

func (shortWriter) Write(value []byte) (int, error) {
	return len(value) - 1, nil
}
