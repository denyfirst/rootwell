package main

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
