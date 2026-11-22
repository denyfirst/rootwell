//go:build linux

package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

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
