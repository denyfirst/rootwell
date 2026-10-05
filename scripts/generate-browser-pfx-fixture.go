//go:build ignore

// Generate disposable, non-production PFX material for browser tests only.
// The default JSON is consumed in-memory by test-browser-pfx.mjs. --write-files
// creates a private OS-temp directory for a manual UI demonstration.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/denyfirst/rootwell/internal/pfxcreate"
)

const password = "synthetic-browser-PFX-2026-fd48"

func main() {
	writeFiles := flag.Bool("write-files", false, "write disposable synthetic files to an OS temp directory")
	flag.Parse()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(2026), Subject: pkix.Name{CommonName: "demo.rootwell.invalid"},
		DNSNames: []string{"demo.rootwell.invalid"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	check(err)
	private, err := x509.MarshalPKCS8PrivateKey(key)
	check(err)
	defer clear(private)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	defer clear(keyPEM)
	pfx, err := pfxcreate.Create(certPEM, keyPEM, nil, password)
	check(err)
	defer clear(pfx)
	if *writeFiles {
		directory, err := os.MkdirTemp("", "rootwell-synthetic-pfx-")
		check(err)
		check(os.WriteFile(filepath.Join(directory, "synthetic-cert.pem"), certPEM, 0o600))
		check(os.WriteFile(filepath.Join(directory, "synthetic-key.pem"), keyPEM, 0o600))
		check(os.WriteFile(filepath.Join(directory, "synthetic-bundle.pfx"), pfx, 0o600))
		check(json.NewEncoder(os.Stdout).Encode(map[string]string{"directory": directory, "password": password}))
		return
	}
	check(json.NewEncoder(os.Stdout).Encode(map[string]string{
		"certificate": base64.StdEncoding.EncodeToString(certPEM),
		"key":         base64.StdEncoding.EncodeToString(keyPEM),
		"pfx":         base64.StdEncoding.EncodeToString(pfx),
		"password":    password,
	}))
}

func check(err error) {
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "synthetic PFX generation failed")
		os.Exit(1)
	}
}
