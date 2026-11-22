//go:build ignore

// Generate disposable, non-production material for the Convert page test:
// a root, an issuing CA and a website certificate, its key (plain and
// password-protected), an unrelated key, an RSA key and a PFX holding the
// certificate, its issuer and its key. Printed as JSON for
// test-convert.mjs; nothing is written to disk.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"github.com/denyfirst/rootwell/internal/pfxcreate"
	"github.com/youmark/pkcs8"
)

const (
	pfxPassword = "synthetic-convert-PFX-2026-a41c"
	keyPassword = "synthetic-convert-key-2026-77e0"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func newKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	return key
}

func issue(template, parent *x509.Certificate, public, signer any) ([]byte, *x509.Certificate) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	check(err)
	parsed, err := x509.ParseCertificate(der)
	check(err)
	return der, parsed
}

func encode(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func main() {
	start := time.Now().Add(-time.Hour)
	rootKey, issuerKey, leafKey, otherKey := newKey(), newKey(), newKey(), newKey()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic Convert Root"},
		NotBefore: start, NotAfter: start.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, root := issue(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	issuerDER, issuer := issue(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic Convert Issuing CA"},
		NotBefore: start, NotAfter: start.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}, root, &issuerKey.PublicKey, rootKey)
	leafDER, _ := issue(&x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "shop.test"},
		DNSNames: []string{"shop.test", "www.shop.test"}, NotBefore: start, NotAfter: start.AddDate(0, 0, 90),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, issuer, &leafKey.PublicKey, issuerKey)
	leafPKCS8, err := x509.MarshalPKCS8PrivateKey(leafKey)
	check(err)
	otherPKCS8, err := x509.MarshalPKCS8PrivateKey(otherKey)
	check(err)
	lockedDER, err := pkcs8.MarshalPrivateKey(leafKey, []byte(keyPassword), &pkcs8.Opts{Cipher: pkcs8.AES256CBC,
		KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 600_000, HMACHash: crypto.SHA256}})
	check(err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	check(err)
	leafPEM, issuerPEM, keyPEM := encode("CERTIFICATE", leafDER), encode("CERTIFICATE", issuerDER), encode("PRIVATE KEY", leafPKCS8)
	pfx, err := pfxcreate.Create(leafPEM, keyPEM, issuerPEM, pfxPassword)
	check(err)
	b64 := base64.StdEncoding.EncodeToString
	check(json.NewEncoder(os.Stdout).Encode(map[string]string{
		"leaf":         b64(leafPEM),
		"issuer":       b64(issuerPEM),
		"root":         b64(encode("CERTIFICATE", rootDER)),
		"key":          b64(keyPEM),
		"locked_key":   b64(encode("ENCRYPTED PRIVATE KEY", lockedDER)),
		"other_key":    b64(encode("PRIVATE KEY", otherPKCS8)),
		"rsa_key":      b64(encode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))),
		"pfx":          b64(pfx),
		"pfx_password": pfxPassword,
		"key_password": keyPassword,
	}))
}
