//go:build ignore

// Generates public, synthetic UI results. Keys exist only in memory, and the
// synthetic root is never installed in any OS or browser trust store.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"time"

	"github.com/denyfirst/rootwell/internal/websitechain"
)

func main() {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	makeChain := func() []*x509.Certificate {
		var chain []*x509.Certificate
		var parent *x509.Certificate
		var signer ed25519.PrivateKey
		for i, name := range []string{"Rootwell Example Root", "Rootwell Example Issuer", "website.example.org"} {
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			mustWebsite(err)
			template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), BasicConstraintsValid: true}
			if i < 2 {
				template.IsCA = true
				template.KeyUsage = x509.KeyUsageCertSign
				template.NotAfter = now.Add(365 * 24 * time.Hour)
			} else {
				template.DNSNames = []string{name}
				template.KeyUsage = x509.KeyUsageDigitalSignature
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}
			if parent == nil {
				parent = template
				signer = key
			}
			der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
			mustWebsite(err)
			c, err := x509.ParseCertificate(der)
			mustWebsite(err)
			chain = append([]*x509.Certificate{c}, chain...)
			parent, signer = c, key
		}
		return chain
	}
	chain, other := makeChain(), makeChain()
	roots := x509.NewCertPool()
	roots.AddCert(chain[2])
	examples := map[string]websitechain.Report{}
	for key, input := range map[string][]*x509.Certificate{"valid": chain[:2], "missing": chain[:1], "wrong": {chain[0], other[1]}} {
		r, err := websitechain.Analyze(input, roots, "website.example.org", now)
		mustWebsite(err)
		r.Address = "192.0.2.10 (example only)"
		r.TLS = "TLS 1.3"
		r.TrustSource = "Synthetic example root — not installed"
		examples[key] = r
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	mustWebsite(encoder.Encode(map[string]any{"synthetic": true, "examples": examples}))
}

func mustWebsite(err error) {
	if err != nil {
		panic("synthetic website example generation failed")
	}
}
