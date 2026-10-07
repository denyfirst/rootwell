package certificatepair

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

func chainFixture(t *testing.T) (leaf, root, key, renewed []byte) {
	t.Helper()
	rp, rk, _ := ed25519.GenerateKey(rand.Reader)
	lp, lk, _ := ed25519.GenerateKey(rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Synthetic issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, err := x509.CreateCertificate(rand.Reader, rt, rt, rp, rk)
	if err != nil {
		t.Fatal("fixture root failed")
	}
	lt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bundle.rootwell.invalid"}, NotBefore: rt.NotBefore, NotAfter: rt.NotAfter}
	leaf, err = x509.CreateCertificate(rand.Reader, lt, rt, lp, rk)
	if err != nil {
		t.Fatal("fixture leaf failed")
	}
	lt.SerialNumber = big.NewInt(2)
	renewed, err = x509.CreateCertificate(rand.Reader, lt, rt, lp, rk)
	if err != nil {
		t.Fatal("fixture renewal failed")
	}
	key, err = x509.MarshalPKCS8PrivateKey(lk)
	if err != nil {
		t.Fatal("fixture key failed")
	}
	return
}

func TestBundleSelectionMatchMismatchAndIssuerRefusals(t *testing.T) {
	leaf, root, key, renewed := chainFixture(t)
	defer clear(key)
	input := PublicPEM([][]byte{root, leaf})
	r, canonical, err := PrepareBundle(input, key, nil, "", "", "")
	if err != nil || r.KeyStatus != "matched" || len(r.BundleDER) != 2 || len(r.IssuerDER) != 1 || !bytes.Equal(r.DER, leaf) || !bytes.Equal(canonical, key) {
		t.Fatal("valid unordered bundle/key refused")
	}
	clear(canonical)
	fp := r.Fingerprint
	_, wrong := pairFixture(t, "ed", false)
	defer clear(wrong)
	r, canonical, err = PrepareBundle(input, wrong, nil, "", "", "")
	if err != nil || r.KeyStatus != "mismatch" || !bytes.Equal(canonical, wrong) {
		t.Fatal("valid mismatch not represented")
	}
	clear(canonical)
	r, canonical, err = PrepareBundle(input, nil, nil, "", "", "")
	if err != nil || r.KeyStatus != "not-added" || r.HasPrivateKey || len(canonical) != 0 {
		t.Fatal("public bundle refused")
	}
	ambiguous := PublicPEM([][]byte{root, renewed, leaf})
	_, canonical, err = PrepareBundle(ambiguous, key, nil, "", "", "")
	var choice *SelectionRequired
	if !errors.As(err, &choice) || len(choice.Candidates) != 2 || len(canonical) != 0 {
		t.Fatal("same-key renewal was guessed or leaked partial key")
	}
	r, canonical, err = PrepareBundle(ambiguous, key, nil, "", "", fp)
	if err != nil || r.Fingerprint != fp || len(r.BundleDER) != 3 {
		t.Fatal("explicit primary refused or collection lost")
	}
	clear(canonical)
	other, _, _, _ := chainFixture(t)
	for _, bad := range [][]byte{PublicPEM([][]byte{leaf, other}), PublicPEM([][]byte{leaf, leaf}), append(input, []byte("secret-sentinel")...), make([]byte, MaxBundleBytes+1)} {
		_, canonical, err = PrepareBundle(bad, key, nil, "", "", fp)
		if err == nil || len(canonical) != 0 {
			t.Fatal("unrelated/duplicate/malformed input accepted")
		}
	}
	// A correctly named issuer with a different signing key is not an issuer.
	_, falseRoot, _, _ := chainFixture(t)
	_, canonical, err = PrepareBundle(PublicPEM([][]byte{leaf, falseRoot}), key, nil, "", "", fp)
	if err == nil || len(canonical) != 0 {
		t.Fatal("name-only issuer accepted")
	}
	for _, algorithm := range []string{"rsa", "ec", "ed"} {
		c, k := pairFixture(t, algorithm, false)
		defer clear(k)
		a, err := Analyze(c, k, nil)
		if err != nil || len(a) != 1 || a[0].KeyStatus != "matched" {
			t.Fatal("valid algorithm refused")
		}
		a, err = Analyze(c, wrong, nil)
		if err != nil || len(a) != 1 || a[0].KeyStatus != "mismatch" {
			t.Fatal("unrelated key accepted as pair or valid mismatch refused")
		}
	}
	_, canonical, err = PrepareBundle(leaf, []byte("secret-sentinel-malformed"), nil, "", "", "")
	if err == nil || len(canonical) != 0 {
		t.Fatal("malformed key mislabeled mismatch")
	}
}

func TestBundleAggregateDERBudget(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("fixture key failed")
	}
	var certificates [][]byte
	for i := int64(1); i <= 9; i++ {
		template := &x509.Certificate{SerialNumber: big.NewInt(i), Subject: pkix.Name{CommonName: "large.rootwell.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: make([]byte, 60<<10)}}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
		if err != nil || len(der) > 64<<10 {
			t.Fatal("fixture certificate failed")
		}
		certificates = append(certificates, der)
	}
	// Both inputs fit the encoded/file limit. Check must share the storage's
	// decoded budget, rather than approve a collection Save cannot retain.
	below := PublicPEM(certificates[:8])
	above := PublicPEM(certificates)
	if len(above) > MaxBundleBytes {
		t.Fatal("fixture exceeds file budget")
	}
	if records, err := Analyze(below, nil, nil); err != nil || len(records) != 8 {
		t.Fatal("within-budget collection refused")
	}
	if records, err := Analyze(above, nil, nil); err == nil || len(records) != 0 {
		t.Fatal("over-budget collection accepted or partial result returned")
	}
	if _, canonical, err := PrepareBundle(above, nil, nil, "", "", ""); err == nil || len(canonical) != 0 {
		t.Fatal("over-budget preparation accepted or partial key returned")
	}
}

func FuzzBundleMatchRefusesMalformedKey(f *testing.F) {
	f.Add([]byte("bad"), []byte("bad"))
	f.Fuzz(func(t *testing.T, certificate, key []byte) {
		if len(certificate) > MaxBundleBytes+1 || len(key) > 64<<10+1 {
			return
		}
		records, err := Analyze(certificate, key, nil)
		if err != nil && len(records) != 0 {
			t.Fatal("partial results on failure")
		}
	})
}
