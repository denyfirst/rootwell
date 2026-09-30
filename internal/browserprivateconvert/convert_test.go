package browserprivateconvert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/youmark/pkcs8"
)

func testKey(t *testing.T, kind string) any {
	t.Helper()
	if kind == "RSA" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	if kind == "Ed25519" {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testInputs(t *testing.T, key any) map[string][]byte {
	t.Helper()
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string][]byte{
		"pkcs8-der": pkcs8DER,
		"pkcs8-pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}),
	}
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(typed)
		inputs["pkcs1-der"] = der
		inputs["pkcs1-pem"] = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(typed)
		if err != nil {
			t.Fatal(err)
		}
		inputs["sec1-der"] = der
		inputs["sec1-pem"] = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	return inputs
}

func TestInspectAndExportEncryptedPrivateKeyFormats(t *testing.T) {
	password := []byte("non-production-output-secret-12345")
	for _, kind := range []string{"RSA", "ECDSA", "Ed25519"} {
		key := testKey(t, kind)
		for format, input := range testInputs(t, key) {
			t.Run(kind+"/"+format, func(t *testing.T) {
				original := bytes.Clone(input)
				info, err := Inspect(input)
				if err != nil || info.Algorithm != kind || info.InputFormat != format || info.Bits < 256 || len(info.PublicFingerprint) != 95 {
					t.Fatalf("inspection: %#v, %v", info, err)
				}
				output, filename, err := ExportEncrypted(input, info.PublicFingerprint, password)
				if err != nil || !strings.HasPrefix(filename, "rootwell-encrypted-key-") || !strings.HasSuffix(filename, ".pem") {
					t.Fatalf("export: %v", err)
				}
				defer clear(output)
				if !bytes.Equal(input, original) || bytes.Contains(output, input) {
					t.Fatal("source changed or appeared in output")
				}
				block, rest := pem.Decode(output)
				if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" || len(rest) != 0 {
					t.Fatal("output is not exactly one encrypted PKCS#8 block")
				}
				if _, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte("wrong-password")); err == nil {
					t.Fatal("wrong password decrypted the output")
				}
				decoded, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, password)
				if err != nil {
					t.Fatalf("decrypt exported key: %v", err)
				}
				decodedDER, err := x509.MarshalPKCS8PrivateKey(decoded)
				if err != nil {
					t.Fatal(err)
				}
				decodedInfo, err := Inspect(decodedDER)
				if err != nil || decodedInfo.PublicFingerprint != info.PublicFingerprint {
					t.Fatal("encrypted output changed the key")
				}
			})
		}
	}
}

func TestPrivateConversionRefusesMalformedChangedAndWeakPassword(t *testing.T) {
	key := testKey(t, "RSA")
	input := testInputs(t, key)["pkcs1-pem"]
	info, err := Inspect(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range [][]byte{nil, []byte("private secret text"), append(bytes.Clone(input), []byte("extra")...), append(bytes.Clone(input), input...), bytes.Repeat([]byte("x"), (64<<10)+1)} {
		if _, err := Inspect(source); err == nil {
			t.Fatal("unsafe source was accepted")
		}
	}
	for _, test := range []struct {
		name     string
		finger   string
		password []byte
	}{
		{"wrong fingerprint", strings.Repeat("AA:", 31) + "AA", []byte("non-production-output-secret-12345")},
		{"malformed fingerprint", "abc", []byte("non-production-output-secret-12345")},
		{"short password", info.PublicFingerprint, []byte("short")},
		{"space password", info.PublicFingerprint, []byte("contains spaces even if long enough")},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, filename, err := ExportEncrypted(input, test.finger, test.password)
			if err == nil || output != nil || filename != "" {
				t.Fatal("unsafe export published bytes")
			}
		})
	}
}

func FuzzInspectPrivateKeyNoSecretEcho(f *testing.F) {
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("secret-password-in-malformed-input"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, err := Inspect(input)
		if err != nil && bytes.Contains([]byte(err.Error()), input) && len(input) > 0 {
			t.Fatal("input echoed in error")
		}
	})
}
