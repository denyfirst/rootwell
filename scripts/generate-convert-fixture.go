//go:build ignore

// Generate disposable, non-production material for the page and engine tests:
// a root, an issuing CA and a website certificate, its key (plain and
// password-protected), an unrelated key, an RSA key, a request (CSR) for the
// website key and a PFX holding the certificate, its issuer and its key.
// The same material also comes as other tools write it: 3DES, RC2,
// password-free and PBMAC1 PFX files, a P7B, one PEM with the certificate,
// key and chain, openssl pkcs12 -nodes output, a certificate after a byte
// order mark, an EC key after its EC PARAMETERS, and an old-style encrypted
// key. Printed as JSON; nothing is written to disk.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"github.com/denyfirst/rootwell/internal/pfxcreate"
	"github.com/youmark/pkcs8"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
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

// p7b is a certs-only PKCS#7 SignedData, as Windows and openssl crl2pkcs7
// write it.
func p7b(certificates ...[]byte) []byte {
	raw := func(class, tag int, content ...[]byte) []byte {
		out, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: bytes.Join(content, nil)})
		check(err)
		return out
	}
	marshal := func(value any) []byte {
		out, err := asn1.Marshal(value)
		check(err)
		return out
	}
	signed := raw(0, asn1.TagSequence, marshal(1), raw(0, asn1.TagSet), raw(0, asn1.TagSequence, marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})),
		raw(2, 0, certificates...), raw(0, asn1.TagSet))
	return raw(0, asn1.TagSequence, marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}), raw(2, 0, signed))
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
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "shop.test"},
		DNSNames: []string{"shop.test", "www.shop.test"}}, leafKey)
	check(err)
	leafPEM, issuerPEM, keyPEM := encode("CERTIFICATE", leafDER), encode("CERTIFICATE", issuerDER), encode("PRIVATE KEY", leafPKCS8)
	pfx, err := pfxcreate.Create(leafPEM, keyPEM, issuerPEM, pfxPassword)
	check(err)
	leaf, err := x509.ParseCertificate(leafDER)
	check(err)
	// PFX files as Windows, older OpenSSL and newer OpenSSL write them.
	legacyPFX, err := pkcs12.LegacyDES.Encode(leafKey, leaf, []*x509.Certificate{issuer}, pfxPassword)
	check(err)
	rc2PFX, err := pkcs12.LegacyRC2.Encode(leafKey, leaf, []*x509.Certificate{issuer}, pfxPassword)
	check(err)
	emptyPFX, err := pkcs12.Modern2023.Encode(leafKey, leaf, []*x509.Certificate{issuer}, "")
	check(err)
	pbmac1PFX, err := pkcs12.Modern2026.Encode(leafKey, leaf, []*x509.Certificate{issuer}, pfxPassword)
	check(err)
	sec1, err := x509.MarshalECPrivateKey(leafKey)
	check(err)
	curve, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	check(err)
	//lint:ignore SA1019 Fixture only: the old format older OpenSSL wrote, which Rootwell reads and never writes.
	oldKey, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", sec1, []byte(keyPassword), x509.PEMCipherAES256)
	check(err)
	nodes := bytes.Join([][]byte{[]byte("Bag Attributes\n    localKeyID: 01 00 00 00\n    friendlyName: shop.test\nsubject=CN=shop.test\nissuer=CN=Synthetic Convert Issuing CA\n"), leafPEM,
		[]byte("Bag Attributes: <No Attributes>\nsubject=CN=Synthetic Convert Issuing CA\nissuer=CN=Synthetic Convert Root\n"), issuerPEM,
		[]byte("Bag Attributes\n    localKeyID: 01 00 00 00\nKey Attributes: <No Attributes>\n"), keyPEM}, nil)
	b64 := base64.StdEncoding.EncodeToString
	check(json.NewEncoder(os.Stdout).Encode(map[string]string{
		"pfx_legacy":      b64(legacyPFX),
		"pfx_rc2":         b64(rc2PFX),
		"pfx_empty":       b64(emptyPFX),
		"pfx_unsupported": b64(pbmac1PFX),
		"p7b":             b64(p7b(leafDER, issuerDER)),
		"combined":        b64(bytes.Join([][]byte{leafPEM, keyPEM, issuerPEM}, nil)),
		"nodes":           b64(nodes),
		"bom_leaf":        b64(append([]byte{0xef, 0xbb, 0xbf}, bytes.ReplaceAll(leafPEM, []byte("\n"), []byte("\r\n"))...)),
		"ec_params_key":   b64(append(encode("EC PARAMETERS", curve), encode("EC PRIVATE KEY", sec1)...)),
		"old_key":         b64(pem.EncodeToMemory(oldKey)),
		"leaf":            b64(leafPEM),
		"issuer":          b64(issuerPEM),
		"root":            b64(encode("CERTIFICATE", rootDER)),
		"key":             b64(keyPEM),
		"locked_key":      b64(encode("ENCRYPTED PRIVATE KEY", lockedDER)),
		"other_key":       b64(encode("PRIVATE KEY", otherPKCS8)),
		"rsa_key":         b64(encode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))),
		"csr":             b64(encode("CERTIFICATE REQUEST", csr)),
		"pfx":             b64(pfx),
		"pfx_password":    pfxPassword,
		"key_password":    keyPassword,
	}))
}
