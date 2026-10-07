package certificatepair

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/youmark/pkcs8"
)

func pairFixture(t *testing.T, algorithm string, ca bool) ([]byte, []byte) {
	t.Helper()
	var key crypto.Signer
	var err error
	switch algorithm {
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ec":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		_, k, e := ed25519.GenerateKey(rand.Reader)
		key, err = k, e
	}
	if err != nil {
		t.Fatal("fixture key creation failed")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pair.rootwell.invalid"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: ca}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal("fixture certificate creation failed")
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("fixture serialization failed")
	}
	return der, private
}

func TestPrepareCertificatePairsAndRefusals(t *testing.T) {
	for _, algorithm := range []string{"rsa", "ec", "ed"} {
		t.Run(algorithm, func(t *testing.T) {
			cert, key := pairFixture(t, algorithm, false)
			defer clear(key)
			r, canonical, err := Prepare(cert, key, nil, "", "Nginx")
			if err != nil || !r.HasPrivateKey || !bytes.Equal(canonical, key) {
				t.Fatal("valid pair refused")
			}
			clear(canonical)
			r, canonical, err = Prepare(cert, nil, nil, "", "")
			if err != nil || r.HasPrivateKey || len(canonical) != 0 {
				t.Fatal("public-only save refused")
			}
			_, wrong := pairFixture(t, algorithm, false)
			defer clear(wrong)
			for _, input := range [][]byte{wrong, []byte("secret-sentinel-invalid"), append(append([]byte{}, key...), 0), make([]byte, 64<<10+1)} {
				r, output, err := Prepare(cert, input, nil, "", "")
				if err == nil || len(output) != 0 || r.Fingerprint != "" {
					t.Fatal("bad/mismatched key accepted or returned partial state")
				}
			}
		})
	}
	cert, key := pairFixture(t, "ed", true)
	defer clear(key)
	if _, output, err := Prepare(cert, key, nil, "", ""); err == nil || len(output) != 0 {
		t.Fatal("CA key custody accepted")
	}
	for _, input := range [][]byte{nil, make([]byte, 96<<10+1), append(append([]byte{}, cert...), cert...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})} {
		if _, output, err := Prepare(input, nil, nil, "", ""); err == nil || len(output) != 0 {
			t.Fatal("invalid certificate accepted")
		}
	}
}

func TestEncryptedKeyPairRequiresCorrectPassword(t *testing.T) {
	cert, key := pairFixture(t, "ed", false)
	defer clear(key)
	parsed, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("fixture parsing failed")
	}
	password := []byte("fixture-key-password-only")
	protected, err := pkcs8.MarshalPrivateKey(parsed, password, &pkcs8.Opts{Cipher: pkcs8.AES256CBC, KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 600000, HMACHash: crypto.SHA256}})
	if err != nil {
		t.Fatal("fixture encryption failed")
	}
	defer clear(protected)
	r, output, err := Prepare(cert, protected, password, "", "")
	if err != nil || !r.HasPrivateKey || !bytes.Equal(output, key) {
		t.Fatal("encrypted matching key refused")
	}
	clear(output)
	for _, wrong := range [][]byte{nil, []byte("not-the-password"), make([]byte, 257)} {
		if _, output, err := Prepare(cert, protected, wrong, "", ""); err == nil || len(output) != 0 {
			t.Fatal("wrong key password accepted")
		}
	}
}

func FuzzPrepareRefusesSecretInCertificate(f *testing.F) {
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----"))
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 96<<10 {
			t.Skip()
		}
		r, key, err := Prepare(input, nil, nil, "", "")
		if len(key) != 0 || (err != nil && r.Fingerprint != "") {
			t.Fatal("partial/secret result")
		}
	})
}
