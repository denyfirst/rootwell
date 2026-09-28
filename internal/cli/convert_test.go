package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConvertPublicCertificateBothDirections(t *testing.T) {
	der := cliTestCertificateDER(t)
	for _, test := range []struct {
		name  string
		input []byte
		to    string
	}{
		{"der to pem", der, "pem"},
		{"pem to der", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "der"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			inputPath := filepath.Join(directory, "input.any")
			outputPath := filepath.Join(directory, "output.any")
			if err := os.WriteFile(inputPath, test.input, 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := Run([]string{"convert", "--output", outputPath, "--to", test.to, "--input", inputPath}, &stdout, &stderr)
			if code != ExitOK || stdout.Len() != 0 || stderr.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			got, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			if test.to == "pem" {
				block, rest := pem.Decode(got)
				if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
					t.Fatal("output is not one clean PEM certificate")
				}
				got = block.Bytes
			}
			if !bytes.Equal(got, der) {
				t.Fatal("conversion changed certificate DER")
			}
			if _, err := x509.ParseCertificate(got); err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" {
				info, err := os.Stat(outputPath)
				if err != nil || info.Mode().Perm()&0o077 != 0 {
					t.Fatalf("output permission is not private: %v, %v", info, err)
				}
			}
			original, err := os.ReadFile(inputPath)
			if err != nil || !bytes.Equal(original, test.input) {
				t.Fatal("input changed")
			}
		})
	}
}

func TestConvertRefusesExistingOutputAndSymlink(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "input")
	outputPath := filepath.Join(directory, "output")
	der := cliTestCertificateDER(t)
	if err := os.WriteFile(inputPath, der, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"convert", "--input", inputPath, "--to", "pem", "--output", outputPath}
	if code := Run(args, &stdout, &stderr); code != ExitFailure || stdout.Len() != 0 {
		t.Fatalf("existing output not refused: code=%d stdout=%q", code, stdout.String())
	}
	if got, _ := os.ReadFile(outputPath); string(got) != "keep" {
		t.Fatal("existing output was changed")
	}
	if matches, _ := filepath.Glob(filepath.Join(directory, ".rootwell-public-*")); len(matches) != 0 {
		t.Fatalf("staging files remain: %v", matches)
	}
	if err := os.Remove(outputPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inputPath, outputPath); err == nil {
		stdout.Reset()
		stderr.Reset()
		if code := Run(args, &stdout, &stderr); code != ExitFailure || stdout.Len() != 0 {
			t.Fatalf("symlink output not refused: code=%d stdout=%q", code, stdout.String())
		}
		if got, _ := os.ReadFile(inputPath); !bytes.Equal(got, der) {
			t.Fatal("symlink target changed")
		}
	}
}

func TestConvertRejectsMalformedSecretAndUsage(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "secret-input")
	outputPath := filepath.Join(directory, "output")
	for _, input := range [][]byte{
		[]byte("-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n"),
		append(cliTestCertificateDER(t), 0),
		[]byte("not a certificate"),
		bytes.Repeat([]byte("x"), 16*1024*1024+1),
	} {
		if err := os.WriteFile(inputPath, input, 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"convert", "--input", inputPath, "--to", "pem", "--output", outputPath}, &stdout, &stderr); code != ExitFailure {
			t.Fatalf("malformed/secret input accepted: code=%d", code)
		}
		if stdout.Len() != 0 || strings.Contains(stderr.String(), inputPath) || strings.Contains(stderr.String(), string(input)) {
			t.Fatalf("input leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
			t.Fatalf("output exists after rejection: %v", err)
		}
	}
	der := cliTestCertificateDER(t)
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err := os.WriteFile(inputPath, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	var bundleOut, bundleErr bytes.Buffer
	if code := Run([]string{"convert", "--input", inputPath, "--to", "der", "--output", outputPath}, &bundleOut, &bundleErr); code != ExitFailure {
		t.Fatalf("bundle accepted: code=%d", code)
	}
	if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("bundle wrote output: %v", err)
	}
	for _, args := range [][]string{
		{"convert"},
		{"convert", "--input", inputPath, "--to", "p12", "--output", outputPath},
		{"convert", "--input", inputPath, "--input", inputPath, "--output", outputPath},
		{"convert", "--input", inputPath, "--to", "der", "--output", ""},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != ExitUsage || stdout.Len() != 0 {
			t.Fatalf("usage accepted: %v code=%d", args, code)
		}
	}
}
