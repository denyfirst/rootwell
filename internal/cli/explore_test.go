package cli

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/publicbundle"
)

func TestExploreCommand(t *testing.T) {
	files := writeCLITestChain(t)
	leaf, err := os.ReadFile(files.leaf)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := os.ReadFile(files.intermediate)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "received.crt")
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})
	if err := os.WriteFile(path, append(leafPEM, intermediate...), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"explore", path}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("Run code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	for _, want := range []string{
		"type: public-certificate-collection\n",
		"certificates: 2\n",
		"verification: not-performed\n",
		"trust-anchor: not-selected\n",
		"certificate-1-encoding: pem\n",
		"certificate-2-encoding: pem\n",
		"certificate-1-sha256: ",
		"certificate-2-sha256: ",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("output lacks %q: %q", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), path) || strings.Contains(stdout.String(), "PRIVATE KEY") {
		t.Fatal("output disclosed input path or secret material")
	}
}

func TestExploreSingleDERIgnoresExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unknown-format.bin")
	if err := os.WriteFile(path, cliTestCertificateDER(t), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"explore", path}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("Run code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "certificates: 1\n") ||
		!strings.Contains(stdout.String(), "certificate-1-encoding: der\n") ||
		!strings.Contains(stdout.String(), "verification: not-performed\n") {
		t.Fatalf("unexpected DER result: %q", stdout.String())
	}
}

func TestExploreDoesNotPrintPartialResultOnDuplicate(t *testing.T) {
	certificate := cliTestCertificateDER(t)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	path := filepath.Join(t.TempDir(), "duplicate.pem")
	if err := os.WriteFile(path, append(bytes.Clone(encoded), encoded...), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"explore", path}, &stdout, &stderr); code != ExitFailure {
		t.Fatalf("Run code = %d", code)
	}
	if stdout.Len() != 0 || stderr.String() != "bundle contains duplicate certificates\n" {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestExploreRejectsMalformedAndSecretInputWithoutEcho(t *testing.T) {
	for _, test := range []struct {
		name  string
		input []byte
	}{
		{name: "malformed", input: []byte("customer-secret-junk")},
		{name: "secret block", input: []byte("-----BEGIN PRIVATE KEY-----\nY3VzdG9tZXItc2VjcmV0\n-----END PRIVATE KEY-----\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "customer-secret.pem")
			if err := os.WriteFile(path, test.input, 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if code := Run([]string{"explore", path}, &stdout, &stderr); code != ExitFailure {
				t.Fatalf("Run code = %d", code)
			}
			if stdout.Len() != 0 || stderr.String() != "input is not a supported public certificate bundle\n" {
				t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestExploreArgumentContract(t *testing.T) {
	for _, args := range [][]string{{"explore"}, {"explore", "one", "two"}} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != ExitUsage {
			t.Fatalf("Run(%q) code = %d", args, code)
		}
		if stdout.Len() != 0 || stderr.String() != "invalid arguments\n" {
			t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
		}
	}
}

func TestExploreOutputEscapesCertificateText(t *testing.T) {
	output := renderExplore([]publicbundle.Entry{{Inspection: certinspect.Result{
		Subject: "name\n\x1b[31m\u202e",
		Issuer:  "issuer\rvalue",
	}}})
	for _, forbidden := range []string{"\x1b", "\u202e", "issuer\rvalue"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains raw control text %q", forbidden)
		}
	}
	for _, escaped := range []string{`\n`, `\x1b`, `\u202e`, `\r`} {
		if !strings.Contains(output, escaped) {
			t.Errorf("output lacks escape %q", escaped)
		}
	}
}

func FuzzExploreOutputIsTerminalSafe(f *testing.F) {
	f.Add("subject", "issuer")
	f.Add("\x1b[31m\u202e", "issuer\r\n")
	f.Fuzz(func(t *testing.T, subject, issuer string) {
		output := renderExplore([]publicbundle.Entry{{Inspection: certinspect.Result{
			Subject: subject,
			Issuer:  issuer,
		}}})
		for _, value := range []byte(output) {
			if value != '\n' && (value < 0x20 || value > 0x7e) {
				t.Fatalf("unsafe output byte 0x%02x", value)
			}
		}
	})
}
