package browserpfx

import (
	"bytes"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/keymatch"
)

func TestPFXRevealReauthenticatesAndMatches(t *testing.T) {
	cert, key := fixture(t)
	defer clear(key)
	bundle, _, err := Create(cert, key, nil, []byte(syntheticPassword))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bundle)
	summary, err := Inspect(bundle, []byte(syntheticPassword))
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(bundle)
	defer clear(before)
	output, err := RevealKey(bundle, []byte(syntheticPassword), summary.Certificates[0].Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(output)
	if !bytes.HasPrefix(output, []byte("-----BEGIN PRIVATE KEY-----\n")) {
		t.Fatal("not PKCS#8 PEM")
	}
	matched, err := keymatch.Match(cert, output)
	if err != nil || !matched.Match {
		t.Fatal("revealed key changed identity")
	}
	if !bytes.Equal(bundle, before) {
		t.Fatal("caller bundle modified")
	}
}

func TestPFXRevealRefusesUnsafeInputs(t *testing.T) {
	cert, key := fixture(t)
	defer clear(key)
	bundle, _, err := Create(cert, key, nil, []byte(syntheticPassword))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bundle)
	summary, err := Inspect(bundle, []byte(syntheticPassword))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := summary.Certificates[0].Fingerprint
	tampered := bytes.Clone(bundle)
	tampered[len(tampered)-8] ^= 1
	defer clear(tampered)
	for _, tc := range []struct {
		name            string
		input, password []byte
		fingerprint     string
	}{
		{"wrong-password", bundle, []byte("wrong"), fingerprint},
		{"empty-password", bundle, nil, fingerprint},
		{"long-password", bundle, bytes.Repeat([]byte("a"), 129), fingerprint},
		{"wrong-identity", bundle, []byte(syntheticPassword), strings.Repeat("AA:", 31) + "AA"},
		{"invalid-fingerprint", bundle, []byte(syntheticPassword), "unknown"},
		{"tampered", tampered, []byte(syntheticPassword), fingerprint},
		{"truncated", bundle[:len(bundle)-1], []byte(syntheticPassword), fingerprint},
		{"trailing", append(bytes.Clone(bundle), 0), []byte(syntheticPassword), fingerprint},
		{"oversized", make([]byte, 1<<20+1), []byte(syntheticPassword), fingerprint},
		{"empty", nil, []byte(syntheticPassword), fingerprint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := RevealKey(tc.input, tc.password, tc.fingerprint)
			defer clear(output)
			if err != ErrInvalid || len(output) != 0 {
				t.Fatal("unsafe reveal released private output")
			}
		})
	}
}
