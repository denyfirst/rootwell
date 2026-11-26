package legacypemkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"maps"
	"testing"
)

const password = "synthetic-legacy-key-password"

// encrypt writes the legacy format with the standard library's own,
// deprecated writer, an implementation independent of Decrypt.
func encrypt(t testing.TB, kind string, der []byte, cipher x509.PEMCipher) *pem.Block {
	t.Helper()
	//lint:ignore SA1019 Test fixtures only: the reader must open what older tools wrote.
	block, err := x509.EncryptPEMBlock(rand.Reader, kind, der, []byte(password), cipher)
	if err != nil {
		t.Fatal(err)
	}
	return block
}

func keys(t testing.TB) map[string][]byte {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"RSA PRIVATE KEY": x509.MarshalPKCS1PrivateKey(rsaKey), "EC PRIVATE KEY": ecDER}
}

var allCiphers = map[string]x509.PEMCipher{"DES-EDE3-CBC": x509.PEMCipher3DES, "AES-128-CBC": x509.PEMCipherAES128, "AES-192-CBC": x509.PEMCipherAES192, "AES-256-CBC": x509.PEMCipherAES256}

func TestDecryptOpensEveryCipherWithItsPassword(t *testing.T) {
	for kind, der := range keys(t) {
		for name, cipher := range allCiphers {
			block := encrypt(t, kind, der, cipher)
			if !IsEncrypted(block) || block.Headers["DEK-Info"][:len(name)] != name {
				t.Fatalf("%s %s: fixture is not the legacy format", kind, name)
			}
			got, err := Decrypt(block, []byte(password))
			if err != nil || !bytes.Equal(got, der) {
				t.Fatalf("%s %s: %v", kind, name, err)
			}
			for _, wrong := range [][]byte{[]byte("not-" + password), []byte(password[:len(password)-1])} {
				if got, err := Decrypt(block, wrong); !errors.Is(err, ErrWrongPassword) || got != nil {
					t.Fatalf("%s %s: a wrong password gave %v", kind, name, err)
				}
			}
		}
	}
}

func TestDecryptRefusesWhatItDoesNotRead(t *testing.T) {
	der := keys(t)["EC PRIVATE KEY"]
	good := encrypt(t, "EC PRIVATE KEY", der, x509.PEMCipherAES256)
	change := func(edit func(*pem.Block)) *pem.Block {
		block := &pem.Block{Type: good.Type, Headers: maps.Clone(good.Headers), Bytes: bytes.Clone(good.Bytes)}
		edit(block)
		return block
	}
	single := encrypt(t, "EC PRIVATE KEY", der, x509.PEMCipherDES)
	for name, block := range map[string]*pem.Block{
		"nothing":        nil,
		"single DES":     single,
		"PKCS#8 label":   change(func(b *pem.Block) { b.Type = "PRIVATE KEY" }),
		"DSA":            change(func(b *pem.Block) { b.Type = "DSA PRIVATE KEY" }),
		"another cipher": change(func(b *pem.Block) { b.Headers["DEK-Info"] = "AES-256-GCM" + b.Headers["DEK-Info"][11:] }),
		"short IV":       change(func(b *pem.Block) { b.Headers["DEK-Info"] = b.Headers["DEK-Info"][:len(b.Headers["DEK-Info"])-2] }),
		"IV not hex": change(func(b *pem.Block) {
			b.Headers["DEK-Info"] = b.Headers["DEK-Info"][:len(b.Headers["DEK-Info"])-2] + "ZZ"
		}),
		"no IV":              change(func(b *pem.Block) { b.Headers["DEK-Info"] = "AES-256-CBC" }),
		"not encrypted":      change(func(b *pem.Block) { b.Headers["Proc-Type"] = "4,MIC-ONLY" }),
		"an extra header":    change(func(b *pem.Block) { b.Headers["Comment"] = "x" }),
		"no DEK-Info":        change(func(b *pem.Block) { delete(b.Headers, "DEK-Info") }),
		"a partial block":    change(func(b *pem.Block) { b.Bytes = b.Bytes[:len(b.Bytes)-1] }),
		"no bytes":           change(func(b *pem.Block) { b.Bytes = nil }),
		"more than 64 KiB":   change(func(b *pem.Block) { b.Bytes = make([]byte, 64<<10+16) }),
		"plain key, headers": {Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: der},
	} {
		if got, err := Decrypt(block, []byte(password)); !errors.Is(err, ErrUnsupported) || got != nil {
			t.Fatalf("%s: got %v, want unsupported", name, err)
		}
	}
	for _, wrong := range [][]byte{nil, bytes.Repeat([]byte("a"), 257)} {
		if _, err := Decrypt(good, wrong); !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("an empty or overlong password gave %v", err)
		}
	}
	damaged := change(func(b *pem.Block) { b.Bytes[0] ^= 1 })
	if _, err := Decrypt(damaged, []byte(password)); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("a damaged key gave %v", err)
	}
}

// Decrypt agrees with the standard library's deprecated reader.
func TestDecryptAgreesWithTheStandardLibrary(t *testing.T) {
	for kind, der := range keys(t) {
		block := encrypt(t, kind, der, x509.PEMCipherAES128)
		//lint:ignore SA1019 Independent reference reader for a test only.
		reference, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt(block, []byte(password))
		if err != nil || !bytes.Equal(got, reference) {
			t.Fatalf("%s: Decrypt differs from the reference reader: %v", kind, err)
		}
	}
}

func FuzzDecryptLegacyKey(f *testing.F) {
	der := keys(f)["EC PRIVATE KEY"]
	block := encrypt(f, "EC PRIVATE KEY", der, x509.PEMCipher3DES)
	f.Add(block.Type, block.Headers["Proc-Type"], block.Headers["DEK-Info"], block.Bytes, []byte(password))
	f.Add("RSA PRIVATE KEY", "4,ENCRYPTED", "AES-256-CBC,00112233445566778899AABBCCDDEEFF", make([]byte, 32), []byte("x"))
	f.Fuzz(func(t *testing.T, kind, procType, dekInfo string, body, secret []byte) {
		block := &pem.Block{Type: kind, Headers: map[string]string{"Proc-Type": procType, "DEK-Info": dekInfo}, Bytes: body}
		got, err := Decrypt(block, secret)
		if err != nil {
			if got != nil || (!errors.Is(err, ErrUnsupported) && !errors.Is(err, ErrWrongPassword)) {
				t.Fatalf("unexpected refusal: %v", err)
			}
			return
		}
		if kind == "RSA PRIVATE KEY" {
			_, err = x509.ParsePKCS1PrivateKey(got)
		} else {
			_, err = x509.ParseECPrivateKey(got)
		}
		if err != nil {
			t.Fatal("returned bytes that are not the named key")
		}
	})
}
