package browserpfx

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/pfxcreate"
	"github.com/denyfirst/rootwell/internal/pfxfixture"
	"github.com/denyfirst/rootwell/internal/pfxinspect"
	"github.com/youmark/pkcs8"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const syntheticPassword = "synthetic-PFX-password-2026-9c42"
const syntheticOutputPassword = "different-synthetic-key-password-2026"

func fixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "synthetic.example"},
		DNSNames: []string{"synthetic.example"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return cert, private
}

func TestCreatePFXFromEncryptedKey(t *testing.T) {
	for _, algorithm := range []string{"EC", "RSA"} {
		t.Run(algorithm, func(t *testing.T) {
			var key crypto.Signer
			var err error
			if algorithm == "RSA" {
				key, err = rsa.GenerateKey(rand.Reader, 2048)
			} else {
				key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer keymatch.ClearParsedKey(key)
			now := time.Now().Add(-time.Hour)
			template := &x509.Certificate{SerialNumber: big.NewInt(73), Subject: pkix.Name{CommonName: "encrypted.synthetic.invalid"},
				DNSNames: []string{"encrypted.synthetic.invalid"}, NotBefore: now, NotAfter: now.Add(time.Hour * 24),
				BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
			cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			currentPassword := []byte("synthetic-existing-key-password-2026")
			encrypted, err := pkcs8.MarshalPrivateKey(key, currentPassword, &pkcs8.Opts{Cipher: pkcs8.AES256CBC,
				KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 10_000, HMACHash: crypto.SHA256}})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(encrypted)
			for _, encoding := range []string{"DER", "PEM"} {
				t.Run(encoding, func(t *testing.T) {
					input := encrypted
					if encoding == "PEM" {
						input = pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encrypted})
						defer clear(input)
					}
					before := bytes.Clone(input)
					defer clear(before)
					output, name, err := CreateWithInputPassword(cert, input, nil, []byte(syntheticPassword), currentPassword)
					if err != nil || !strings.HasSuffix(name, ".pfx") {
						t.Fatalf("encrypted create failed: %v", err)
					}
					defer clear(output)
					if !bytes.Equal(input, before) {
						t.Fatal("caller-owned key was modified")
					}
					opened, err := Inspect(output, []byte(syntheticPassword))
					if err != nil || len(opened.Certificates) != 1 {
						t.Fatalf("PFX round trip failed: %v", err)
					}
					actual, _, err := ExportCertificate(output, []byte(syntheticPassword), opened.Certificates[0].Fingerprint, "der")
					if err != nil || !bytes.Equal(actual, cert) {
						t.Fatal("PFX changed the input certificate")
					}
					revealed, err := RevealKey(output, []byte(syntheticPassword), opened.Certificates[0].Fingerprint)
					if err != nil {
						t.Fatal(err)
					}
					defer clear(revealed)
					matched, err := keymatch.Match(cert, revealed)
					if err != nil || !matched.Match {
						t.Fatal("revealed RSA/EC key changed identity")
					}
					if _, err := Inspect(output, currentPassword); err == nil {
						t.Fatal("input password unlocked output PFX")
					}
				})
			}
		})
	}
}

func TestEncryptedPFXCreationRefusesUnsafeInputs(t *testing.T) {
	cert, plain := fixture(t)
	defer clear(plain)
	parsed, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		t.Fatal(err)
	}
	defer keymatch.ClearParsedKey(parsed)
	currentPassword := []byte("synthetic-existing-key-password-2026")
	options := &pkcs8.Opts{Cipher: pkcs8.AES256CBC, KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 1000, HMACHash: crypto.SHA256}}
	encrypted, err := pkcs8.MarshalPrivateKey(parsed, currentPassword, options)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encrypted)
	otherCert, otherKey := fixture(t)
	defer clear(otherKey)
	for _, tc := range []struct {
		name                                              string
		certificate, key, password, outputPassword, chain []byte
	}{
		{"missing-password", cert, encrypted, nil, []byte(syntheticPassword), nil},
		{"wrong-password", cert, encrypted, []byte("wrong"), []byte(syntheticPassword), nil},
		{"unrelated-certificate", otherCert, encrypted, currentPassword, []byte(syntheticPassword), nil},
		{"unexpected-password-for-plaintext", cert, plain, currentPassword, []byte(syntheticPassword), nil},
		{"reused-password", cert, encrypted, currentPassword, currentPassword, nil},
		{"long-password", cert, encrypted, bytes.Repeat([]byte("A"), 257), []byte(syntheticPassword), nil},
		{"truncated-key", cert, encrypted[:len(encrypted)-1], currentPassword, []byte(syntheticPassword), nil},
		{"trailing-key", cert, append(bytes.Clone(encrypted), 0), currentPassword, []byte(syntheticPassword), nil},
		{"bad-chain", cert, encrypted, currentPassword, []byte(syntheticPassword), []byte("not a chain")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, name, err := CreateWithInputPassword(tc.certificate, tc.key, tc.chain, tc.outputPassword, tc.password)
			if err == nil || output != nil || name != "" {
				clear(output)
				t.Fatal("unsafe input produced output")
			}
			if err.Error() != ErrInvalid.Error() {
				t.Fatal("failure exposed variable diagnostics")
			}
		})
	}
}

func TestCreateInspectExtractAndRefuse(t *testing.T) {
	cert, key := fixture(t)
	defer clear(key)
	pfx, name, err := Create(cert, key, nil, []byte(syntheticPassword))
	if err != nil || !strings.HasSuffix(name, ".pfx") {
		t.Fatalf("create: %v", err)
	}
	defer clear(pfx)
	summary, err := Inspect(pfx, []byte(syntheticPassword))
	if err != nil || len(summary.Certificates) != 1 || !summary.Certificates[0].MatchingKey {
		t.Fatalf("inspect: %v, %+v", err, summary)
	}
	fingerprint := summary.Certificates[0].Fingerprint
	der, _, err := ExportCertificate(pfx, []byte(syntheticPassword), fingerprint, "der")
	if err != nil || !bytes.Equal(der, cert) {
		t.Fatalf("DER export: %v", err)
	}
	pemBytes, _, err := ExportCertificate(pfx, []byte(syntheticPassword), fingerprint, "pem")
	publicBlock, _ := pem.Decode(pemBytes)
	if err != nil || publicBlock == nil || !bytes.Equal(publicBlock.Bytes, cert) {
		t.Fatalf("PEM export: %v", err)
	}
	encrypted, _, err := ExportKey(pfx, []byte(syntheticPassword), fingerprint, []byte(syntheticOutputPassword))
	if err != nil || !bytes.HasPrefix(encrypted, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\n")) {
		t.Fatalf("key export: %v", err)
	}
	block, _ := pem.Decode(encrypted)
	decoded, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(syntheticOutputPassword))
	if err != nil || decoded == nil {
		t.Fatalf("encrypted output cannot be opened: %v", err)
	}
	clear(encrypted)
	wrong := []byte("wrong-password")
	if result, err := Inspect(pfx, wrong); err == nil || len(result.Certificates) != 0 {
		t.Fatal("wrong PFX password accepted")
	}
	if output, _, err := ExportCertificate(pfx, wrong, fingerprint, "pem"); err == nil || output != nil {
		t.Fatal("wrong password exported certificate")
	}
	if output, _, err := ExportKey(pfx, wrong, fingerprint, []byte(syntheticOutputPassword)); err == nil || output != nil {
		t.Fatal("wrong password exported key")
	}
	other := strings.Repeat("AA:", 31) + "AA"
	if other == fingerprint {
		t.Fatal("unexpected test fingerprint")
	}
	if output, _, err := ExportKey(pfx, []byte(syntheticPassword), other, []byte(syntheticOutputPassword)); err == nil || output != nil {
		t.Fatal("wrong fingerprint exported key")
	}
	if output, _, err := ExportCertificate(pfx, []byte(syntheticPassword), other, "pem"); err == nil || output != nil {
		t.Fatal("wrong fingerprint exported certificate")
	}
	if output, _, err := ExportCertificate(pfx, []byte(syntheticPassword), fingerprint, "crt"); err == nil || output != nil {
		t.Fatal("unsupported output format exported certificate")
	}
	if output, _, err := ExportKey(pfx, []byte(syntheticPassword), fingerprint, []byte(syntheticPassword)); err == nil || output != nil {
		t.Fatal("reused PFX password exported key")
	}
	if output, _, err := Create(cert, []byte("not a key"), nil, []byte(syntheticPassword)); err == nil || output != nil {
		t.Fatal("mismatched key accepted")
	}
	if output, _, err := Create(cert, key, nil, []byte("short")); err == nil || output != nil {
		t.Fatal("weak output password accepted")
	}
	tampered := bytes.Clone(pfx)
	tampered[len(tampered)-8] ^= 1
	if result, err := Inspect(tampered, []byte(syntheticPassword)); err == nil || len(result.Certificates) != 0 {
		t.Fatal("tampered PFX accepted")
	}
	if result, err := Inspect(append(bytes.Clone(pfx), 0), []byte(syntheticPassword)); err == nil || len(result.Certificates) != 0 {
		t.Fatal("PFX trailing data accepted")
	}
	if pfxinspect.Preflight(pfx) != nil {
		t.Fatal("created PFX failed preflight")
	}
}

func windowsChain(t *testing.T) (*x509.Certificate, *x509.Certificate, crypto.Signer) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(50), Subject: pkix.Name{CommonName: "Synthetic Windows CA"}, NotBefore: now, NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(51), Subject: pkix.Name{CommonName: "iis.synthetic.test"}, DNSNames: []string{"iis.synthetic.test"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, ca, key
}

// Every PFX output works on a Windows 3DES file with the issuer first and on
// a PFX without a password; a wrong password is named as one.
func TestPFXOutputsOpenWindowsAndPasswordlessPFX(t *testing.T) {
	leaf, ca, key := windowsChain(t)
	passwordless, err := pkcs12.Modern2023.Encode(key, leaf, []*x509.Certificate{ca}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		input    []byte
		password []byte
	}{
		{"Windows 3DES", pfxfixture.Windows(t, leaf, ca, key, syntheticPassword).Build(t), []byte(syntheticPassword)},
		{"no password", passwordless, nil},
	} {
		summary, err := Inspect(tc.input, tc.password)
		if err != nil || len(summary.Certificates) != 2 || !summary.Certificates[0].MatchingKey {
			t.Fatalf("%s: inspect: %v", tc.name, err)
		}
		fingerprint := summary.Certificates[0].Fingerprint
		if der, _, err := ExportCertificate(tc.input, tc.password, fingerprint, "der"); err != nil || !bytes.Equal(der, leaf.Raw) {
			t.Fatalf("%s: certificate: %v", tc.name, err)
		}
		if locked, _, err := ExportKey(tc.input, tc.password, fingerprint, []byte(syntheticOutputPassword)); err != nil || !bytes.HasPrefix(locked, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
			t.Fatalf("%s: locked key: %v", tc.name, err)
		}
		plain, err := RevealKey(tc.input, tc.password, fingerprint)
		if err != nil {
			t.Fatalf("%s: key: %v", tc.name, err)
		}
		if matched, err := keymatch.Match(leaf.Raw, plain); err != nil || !matched.Match {
			t.Fatalf("%s: the key does not belong to the certificate", tc.name)
		}
		clear(plain)
		_, err = Inspect(tc.input, []byte("not-the-password"))
		if !errors.Is(err, ErrInvalid) || pfxinspect.Code(err) != "wrong-password" {
			t.Fatalf("%s: a wrong password was not named as one: %v", tc.name, err)
		}
	}
}

func TestCreateOlderWindowsProfileReadsBack(t *testing.T) {
	cert, key := fixture(t)
	defer clear(key)
	output, _, err := CreateProfile(cert, key, nil, []byte(syntheticPassword), nil, pfxcreate.OlderWindows)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output, []byte{0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03}) {
		t.Fatal("the older Windows PFX is not 3DES")
	}
	if summary, err := Inspect(output, []byte(syntheticPassword)); err != nil || len(summary.Certificates) != 1 {
		t.Fatalf("the older Windows PFX does not read back: %v", err)
	}
}
