package publicinventory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// Public certificates made for these tests from fixed key seeds, so every call
// returns the same bytes. They replace files that once shipped as page demos.

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func testIssue(t testing.TB, template, parent *x509.Certificate, key, signer ed25519.PrivateKey) (*x509.Certificate, []byte) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// testCertificate is a self-signed website certificate for two names, valid
// from 2026 to 2031.
func testCertificate(t testing.TB) []byte {
	t.Helper()
	key := testKey(1)
	template := &x509.Certificate{SerialNumber: big.NewInt(2026092401),
		Subject:   pkix.Name{Organization: []string{"Rootwell test"}, CommonName: "www.rootwell.test"},
		DNSNames:  []string{"www.rootwell.test", "api.rootwell.test"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	_, out := testIssue(t, template, template, key, key)
	return out
}

// testChain is a website certificate, the CA that issued it and their root.
func testChain(t testing.TB) (leaf, intermediate, root []byte) {
	t.Helper()
	start, end := time.Date(2026, 9, 24, 23, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	rootKey, issuerKey, leafKey := testKey(2), testKey(3), testKey(4)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Rootwell Test Root"},
		NotBefore: start, NotAfter: end, IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign}
	rootCertificate, root := testIssue(t, rootTemplate, rootTemplate, rootKey, rootKey)
	issuer, intermediate := testIssue(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Rootwell Test Intermediate"},
		NotBefore: start, NotAfter: end, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign}, rootCertificate, issuerKey, rootKey)
	_, leaf = testIssue(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "chain.rootwell.test"},
		DNSNames: []string{"chain.rootwell.test"}, NotBefore: start, NotAfter: end, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, issuer, leafKey, issuerKey)
	return leaf, intermediate, root
}

// testRoot is the self-signed root of testChain.
func testRoot(t testing.TB) []byte {
	t.Helper()
	_, _, root := testChain(t)
	return root
}

// testChainFiles is testChain in one PEM file, website certificate first.
func testChainFiles(t testing.TB) []byte {
	t.Helper()
	leaf, intermediate, root := testChain(t)
	return bytes.Join([][]byte{leaf, intermediate, root}, nil)
}
