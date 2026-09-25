// This test helper writes only generated, non-production public certificates
// to stdout. Its signing keys exist solely in this process's memory.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

func main() {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	// Static public demo assets have a bounded, non-production validity window.
	// They must never be installed as a browser or OS trust anchor.
	demoExpiry := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		return public, private
	}
	rootPublic, rootKey := key()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Rootwell Browser Test Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: demoExpiry,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootKey)
	must(err)
	root, err := x509.ParseCertificate(rootDER)
	must(err)
	intermediatePublic, intermediateKey := key()
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Rootwell Browser Test Intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: demoExpiry,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, intermediatePublic, rootKey)
	must(err)
	intermediate, err := x509.ParseCertificate(intermediateDER)
	must(err)
	leafPublic, _ := key()
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "verify.rootwell.invalid"},
		DNSNames:  []string{"verify.rootwell.invalid"},
		NotBefore: now.Add(-time.Hour), NotAfter: demoExpiry,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, leafPublic, intermediateKey)
	must(err)
	encode := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	leaf, intermediatePEM, rootPEM := encode(leafDER), encode(intermediateDER), encode(rootDER)
	must(json.NewEncoder(os.Stdout).Encode(map[string]string{
		"hostname": "verify.rootwell.invalid", "evaluated_at": now.Format(time.RFC3339),
		"leaf": leaf, "intermediate": intermediatePEM, "root": rootPEM,
		"source": leaf + intermediatePEM + rootPEM,
	}))
}

func must(err error) {
	if err != nil {
		panic("non-production test fixture generation failed")
	}
}
