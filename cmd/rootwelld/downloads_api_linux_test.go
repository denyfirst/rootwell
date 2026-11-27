//go:build linux

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// A PFX for Windows and IIS holds the certificate, its issuers and its key,
// locked with the download password, in the modern protection or the one
// Windows Server 2016 reads; like any key download, it needs a fresh code.
func TestLinuxAPFXForWindowsHoldsTheChainAndTheKey(t *testing.T) {
	_, cookie, e := readyGate(t)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic Issuing CA"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	root, _ := x509.ParseCertificate(caDER)
	// An intermediate between the root and the certificate.
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Synthetic Intermediate CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(36 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, root, &interKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(interDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "iis.rootwell.invalid"},
		DNSNames: []string{"iis.rootwell.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	// Saved with the whole chain, root included: the PFX leaves the root out.
	bundle := append(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})...),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	record, canonical, err := certificatepair.PrepareBundle(bundle, key, nil, "", "", "")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if w := post(t, e, cookie, "/api/certificates/save", map[string]any{"certificate": bundle, "private_key": key, "expected_generation": 1, "fingerprint": record.Fingerprint, "allow_mismatch": false}); w.code != http.StatusCreated {
		t.Fatalf("save: %d %s", w.code, w.body)
	}
	const password = "a-strong-download-password-2026"
	for _, older := range []bool{false, true} {
		body := map[string]any{"fingerprint": record.Fingerprint, "expected_generation": 2, "pair": false, "pfx": true, "output_password": []byte(password)}
		if older {
			body["older_windows"] = true
		}
		w := post(t, e, cookie, "/api/certificates/download", body)
		if w.code != http.StatusOK || w.header.Get("Content-Type") != "application/x-pkcs12" {
			t.Fatalf("older %v: %d %s", older, w.code, w.body)
		}
		private, leaf, issuers, err := pkcs12.DecodeChain(w.body, password)
		if err != nil {
			t.Fatalf("older %v: the PFX does not open with its password: %v", older, err)
		}
		if !leaf.Equal(must(x509.ParseCertificate(leafDER))) || len(issuers) != 1 || !issuers[0].Equal(ca) || !private.(*ecdsa.PrivateKey).Equal(leafKey) {
			t.Fatalf("older %v: the PFX does not hold the certificate, its issuer and its key", older)
		}
		if _, _, _, err := pkcs12.DecodeChain(w.body, "another-password-of-twenty-chars"); err == nil {
			t.Fatalf("older %v: the PFX opens with another password", older)
		}
	}
	for name, body := range map[string]map[string]any{
		"a PFX and a ZIP":        {"fingerprint": record.Fingerprint, "expected_generation": 2, "pair": true, "pfx": true, "output_password": []byte(password)},
		"older Windows alone":    {"fingerprint": record.Fingerprint, "expected_generation": 2, "pair": true, "older_windows": true, "output_password": []byte(password)},
		"a PFX with no password": {"fingerprint": record.Fingerprint, "expected_generation": 2, "pair": false, "pfx": true},
		"a short password":       {"fingerprint": record.Fingerprint, "expected_generation": 2, "pair": false, "pfx": true, "output_password": []byte("short")},
	} {
		if w := post(t, e, cookie, "/api/certificates/download", body); w.code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, w.code, w.body)
		}
	}
	e.clock.add(freshLife)
	if w := post(t, e, cookie, "/api/certificates/download", map[string]any{"fingerprint": record.Fingerprint, "expected_generation": 2, "pair": false, "pfx": true, "output_password": []byte(password)}); w.code != http.StatusPreconditionRequired {
		t.Fatalf("a PFX without a fresh code: %d %s", w.code, w.body)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
