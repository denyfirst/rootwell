package acmecertrequest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestCertificateRequestExactNamesSeparateKeyAndStrictRefusal(t *testing.T) {
	names := []string{"*.example.com", "example.com"}
	private, csr, summary, err := Create(names)
	defer clear(private)
	if err != nil || len(private) == 0 || len(csr) == 0 || !summary.SignatureChecked || summary.PublicFingerprint == "" {
		t.Fatal("valid request refused")
	}
	if checked, err := Check(private, csr, names); err != nil || checked.PublicFingerprint != summary.PublicFingerprint || checked.RequestFingerprint != summary.RequestFingerprint {
		t.Fatal("owned request did not round trip")
	}
	other, _, otherSummary, err := Create(names)
	defer clear(other)
	if err != nil || bytes.Equal(private, other) || summary.PublicFingerprint == otherSummary.PublicFingerprint {
		t.Fatal("new request reused another key")
	}
	badCSR := bytes.Clone(csr)
	badCSR[len(badCSR)-1] ^= 1
	for _, tc := range []struct {
		key, csr []byte
		names    []string
	}{
		{other, csr, names}, {private, badCSR, names}, {private, append(bytes.Clone(csr), 0), names}, {private, csr, []string{"example.com"}},
		{nil, csr, names}, {private, nil, names}, {bytes.Repeat([]byte{1}, 513), csr, names}, {private, bytes.Repeat([]byte{1}, 4097), names},
	} {
		if out, err := Check(tc.key, tc.csr, tc.names); err == nil || out.PublicFingerprint != "" {
			t.Fatal("unsafe/partial request accepted")
		}
	}
	parsed, _ := x509.ParsePKCS8PrivateKey(private)
	unwanted, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "unwanted"}, DNSNames: names}, parsed)
	if _, err := Check(private, unwanted, names); err == nil {
		t.Fatal("unwanted subject accepted")
	}
	curve, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	curveKey, _ := x509.MarshalPKCS8PrivateKey(curve)
	defer clear(curveKey)
	if _, err := Check(curveKey, csr, names); err == nil {
		t.Fatal("unsupported curve accepted")
	}
	for _, n := range [][]string{nil, {"example.com", "*.example.com"}, {"example.com", "example.com"}, {"evil.local"}} {
		key, csr, s, err := Create(n)
		clear(key)
		if err == nil || key != nil || csr != nil || s.PublicFingerprint != "" {
			t.Fatal("invalid names created partial material")
		}
	}
}

func FuzzCertificateRequestBinding(f *testing.F) {
	names := []string{"example.com"}
	private, csr, _, err := Create(names)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(private, csr)
	f.Add([]byte("bad"), csr)
	f.Add(private, []byte("bad"))
	f.Fuzz(func(t *testing.T, key, csr []byte) {
		if len(key) > 513 || len(csr) > 4097 {
			return
		}
		s, err := Check(key, csr, names)
		if err != nil && (s.PublicFingerprint != "" || s.SignatureChecked) {
			t.Fatal("partial authority on malformed request")
		}
	})
}
