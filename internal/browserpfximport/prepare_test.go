package browserpfximport

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/keymatch"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const fixturePassword = "synthetic-pfx-import-password-2026"

func fixture(t *testing.T, rsaKey bool) (crypto.Signer, *x509.Certificate, []*x509.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keymatch.ClearParsedKey(rootKey) })
	now := time.Now().Add(-time.Hour)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic PFX import root"}, NotBefore: now, NotAfter: now.Add(48 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	var key crypto.Signer
	if rsaKey {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keymatch.ClearParsedKey(key) })
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "pfx-import.synthetic.invalid"}, DNSNames: []string{"pfx-import.synthetic.invalid"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return key, leaf, []*x509.Certificate{root}
}

func TestPreparePreservesPublicCollectionAndOnlyEncryptsMatchingKey(t *testing.T) {
	for _, rsaKey := range []bool{false, true} {
		key, leaf, chain := fixture(t, rsaKey)
		input, err := pkcs12.Modern2023.Encode(key, leaf, chain, fixturePassword)
		if err != nil {
			t.Fatal(err)
		}
		before := bytes.Clone(input)
		p, err := Prepare(input, []byte(fixturePassword))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(input, before) || !bytes.HasPrefix(p.PrivateKey, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) || bytes.Contains(p.PrivateKey, []byte("-----BEGIN PRIVATE KEY-----")) || len(p.KeyPassword) != 43 || bytes.Equal(p.KeyPassword, []byte(fixturePassword)) {
			t.Fatal("input changed or plaintext/reused password escaped")
		}
		record, canonical, err := certificatepair.PrepareBundle(p.Certificate, p.PrivateKey, p.KeyPassword, "", "", p.Fingerprint)
		if err != nil || record.KeyStatus != "matched" || !record.HasPrivateKey || len(record.BundleDER) != 2 || len(record.IssuerDER) != 1 || !bytes.Equal(record.DER, leaf.Raw) {
			t.Fatal("prepared API material failed independent validation", err)
		}
		if result, err := keymatch.Match(leaf.Raw, canonical); err != nil || !result.Match {
			t.Fatal("wrong key prepared")
		}
		clear(canonical)
		if _, canonical, err := certificatepair.PrepareBundle(p.Certificate, p.PrivateKey, []byte("wrong-password"), "", "", p.Fingerprint); err == nil {
			clear(canonical)
			t.Fatal("output key not encrypted")
		}
		p.Clear()
		if !allZero(p.Certificate) || !allZero(p.PrivateKey) || !allZero(p.KeyPassword) {
			t.Fatal("owned result not cleared")
		}
	}
}

func TestPrepareRefusesWrongPasswordTamperLegacyAndUnrelatedWithoutPartialMaterial(t *testing.T) {
	key, leaf, chain := fixture(t, false)
	input, err := pkcs12.Modern2023.Encode(key, leaf, chain, fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := pkcs12.Legacy.Encode(key, leaf, chain, fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, other, otherChain := fixture(t, false)
	unrelated, err := pkcs12.Modern2023.Encode(key, leaf, append(chain, other, otherChain[0]), fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedCA, err := pkcs12.Modern2023.Encode(key, leaf, append(chain, otherChain[0]), fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := *other
	caTemplate.IsCA = true
	caTemplate.BasicConstraintsValid = true
	caTemplate.KeyUsage = x509.KeyUsageCertSign
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, otherKey.Public(), otherKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pkcs12.Modern2023.Encode(otherKey, caCert, nil, fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(input)
	tampered[len(tampered)-1] ^= 1
	mismatch, err := pkcs12.Modern2023.Encode(otherKey, leaf, chain, fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	renewedTemplate := *leaf
	renewedTemplate.SerialNumber = big.NewInt(99)
	renewedDER, err := x509.CreateCertificate(rand.Reader, &renewedTemplate, &renewedTemplate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := x509.ParseCertificate(renewedDER)
	if err != nil {
		t.Fatal(err)
	}
	ambiguous, err := pkcs12.Modern2023.Encode(key, leaf, append(chain, renewed), fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, password []byte }{{nil, []byte(fixturePassword)}, {input, nil}, {input, []byte("wrong-password")}, {tampered, []byte(fixturePassword)}, {legacy, []byte(fixturePassword)}, {unrelated, []byte(fixturePassword)}, {unrelatedCA, []byte(fixturePassword)}, {ca, []byte(fixturePassword)}, {mismatch, []byte(fixturePassword)}, {ambiguous, []byte(fixturePassword)}, {make([]byte, (1<<20)+1), []byte(fixturePassword)}, {input, make([]byte, 129)}} {
		p, err := Prepare(tc.input, tc.password)
		if err == nil || len(p.Certificate) != 0 || len(p.PrivateKey) != 0 || len(p.KeyPassword) != 0 || p.Fingerprint != "" {
			p.Clear()
			t.Fatal("refusal returned partial material")
		}
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
