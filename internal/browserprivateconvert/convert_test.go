package browserprivateconvert

import (
	"bytes"
	"crypto"
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

func TestEncryptedInputAndPlaintextTargets(t *testing.T) {
	inputPassword := []byte("test-only-current-password")
	outputPassword := []byte("test-only-new-output-password-123")
	for _, kind := range []string{"RSA", "ECDSA", "Ed25519"} {
		key := testKey(t, kind)
		plain := testInputs(t, key)["pkcs8-der"]
		plainInfo, err := Inspect(plain)
		if err != nil {
			t.Fatal(err)
		}
		opts := &pkcs8.Opts{Cipher: pkcs8.AES256CBC, KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 100_000, HMACHash: crypto.SHA256}}
		ciphertext, err := pkcs8.MarshalPrivateKey(key, inputPassword, opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, input := range [][]byte{ciphertext, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: ciphertext})} {
			if _, err := InspectWithPassword(input, nil); err != ErrInputPasswordRequired {
				t.Fatalf("missing password not recognized: %v", err)
			}
			if _, err := InspectWithPassword(input, []byte("wrong")); err == nil {
				t.Fatal("wrong password accepted")
			}
			info, err := InspectWithPassword(input, inputPassword)
			if err != nil || info.PublicFingerprint != plainInfo.PublicFingerprint || !strings.HasPrefix(info.InputFormat, "encrypted-pkcs8-") {
				t.Fatalf("encrypted inspection: %#v %v", info, err)
			}
			if output, name, err := Export(input, info.PublicFingerprint, []byte("wrong"), "pkcs8-pem", nil); err == nil || output != nil || name != "" {
				t.Fatal("wrong input password published plaintext")
			}
			if output, name, err := Export(input, info.PublicFingerprint, inputPassword, "encrypted-pkcs8-pem", inputPassword); err == nil || output != nil || name != "" {
				t.Fatal("reused input password was accepted for encrypted output")
			}
			formats := []string{"pkcs8-pem", "pkcs8-der", "encrypted-pkcs8-pem"}
			if kind == "RSA" {
				formats = append(formats, "pkcs1-pem", "pkcs1-der")
			}
			if kind == "ECDSA" {
				formats = append(formats, "sec1-pem", "sec1-der")
			}
			for _, format := range formats {
				password := []byte(nil)
				if format == "encrypted-pkcs8-pem" {
					password = outputPassword
				}
				output, filename, err := Export(input, info.PublicFingerprint, inputPassword, format, password)
				if err != nil || len(output) == 0 || !strings.HasSuffix(filename, "."+format[len(format)-3:]) {
					t.Fatalf("%s/%s export: %v %q", kind, format, err, filename)
				}
				if format == "encrypted-pkcs8-pem" {
					if _, err := InspectWithPassword(output, outputPassword); err != nil {
						t.Fatal(err)
					}
				} else {
					decoded, err := Inspect(output)
					if err != nil || decoded.PublicFingerprint != info.PublicFingerprint {
						t.Fatalf("plaintext changed key: %v", err)
					}
				}
				clear(output)
			}
		}
		if kind == "RSA" {
			pemInput := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: ciphertext})
			for _, malformed := range [][]byte{
				append(bytes.Clone(pemInput), pemInput...),
				append(bytes.Clone(ciphertext), 0),
				pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: ciphertext}),
			} {
				if _, err := InspectWithPassword(malformed, inputPassword); err == nil {
					t.Fatal("malformed encrypted input accepted")
				}
			}
		}
	}
}

func TestEncryptedInputRefusesUnsafeProfilesAndNoPartialExport(t *testing.T) {
	key := testKey(t, "RSA")
	goodPassword := []byte("test-only-current-password")
	for _, test := range []struct {
		name string
		opts *pkcs8.Opts
	}{
		{"excessive-kdf", &pkcs8.Opts{Cipher: pkcs8.AES256CBC, KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 1_000_001, HMACHash: crypto.SHA256}}},
		{"sha1", &pkcs8.Opts{Cipher: pkcs8.AES256CBC, KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 100, HMACHash: crypto.SHA1}}},
		{"short-salt", &pkcs8.Opts{Cipher: pkcs8.AES256CBC, KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 4, IterationCount: 100, HMACHash: crypto.SHA256}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, err := pkcs8.MarshalPrivateKey(key, goodPassword, test.opts)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := InspectWithPassword(input, goodPassword); err == nil {
				t.Fatal("unsupported profile accepted")
			}
		})
	}
	plain := testInputs(t, key)["pkcs8-der"]
	info, _ := Inspect(plain)
	for _, test := range []struct {
		name        string
		input       []byte
		inPassword  []byte
		format      string
		outPassword []byte
	}{
		{"mismatched-target", plain, nil, "sec1-pem", nil},
		{"unknown-target", plain, nil, "pfx", nil},
		{"plaintext-with-password", plain, nil, "pkcs8-pem", []byte("unexpected")},
		{"unencrypted-input-with-password", plain, goodPassword, "pkcs8-pem", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, filename, err := Export(test.input, info.PublicFingerprint, test.inPassword, test.format, test.outPassword)
			if err == nil || output != nil || filename != "" {
				t.Fatal("unsafe export returned key material")
			}
		})
	}
}

func FuzzInspectPrivateKeyNoSecretEcho(f *testing.F) {
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("secret-password-in-malformed-input"))
	f.Add([]byte("p")) // A short input can occur inside a fixed public error message.
	f.Fuzz(func(t *testing.T, input []byte) {
		_, err := Inspect(input)
		// Inspect must return only these exact, public sentinels. Looking for
		// arbitrary input substrings in the error yields false positives for
		// short inputs that happen to occur in a fixed error message.
		if err != nil && err != ErrInvalid && err != ErrInputPasswordRequired {
			t.Fatal("inspection returned a non-public error")
		}
	})
}

func FuzzEncryptedProfileNoPanic(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n"))
	f.Add(bytes.Repeat([]byte{0xff}, 257))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64<<10 {
			return
		}
		_, _, _, _ = encryptedDER(input)
	})
}
