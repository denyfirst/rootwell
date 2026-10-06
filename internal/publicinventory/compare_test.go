package publicinventory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"
)

func TestComparisonTracksAllNamesKeyAndDatesWithoutTrust(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://rootwell.invalid/old")
	a := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "old.invalid"}, DNSNames: []string{"EXAMPLE.invalid", "old.invalid"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}, EmailAddresses: []string{"Old@rootwell.invalid"}, URIs: []*url.URL{u}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	old, err := x509.CreateCertificate(rand.Reader, a, a, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	b := *a
	b.SerialNumber = big.NewInt(2)
	b.DNSNames = []string{"example.invalid", "new.invalid"}
	b.NotAfter = a.NotAfter.AddDate(1, 0, 0)
	newer, err := x509.CreateCertificate(rand.Reader, &b, &b, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Compare(old, newer)
	if err != nil || d.SameCertificate || !d.SamePublicKey || !d.ExpiryExtended || !d.ValidityChanged || d.Verification != "not-performed" || !slices.Equal(d.AddedNames, []string{"DNS:new.invalid"}) || !slices.Equal(d.RemovedNames, []string{"DNS:old.invalid"}) {
		t.Fatalf("comparison: %+v %v", d, err)
	}
	same, err := Compare(old, old)
	if err != nil || !same.SameCertificate || !same.SamePublicKey || same.ValidityChanged || same.ExpiryExtended || len(same.AddedNames) != 0 {
		t.Fatal("same certificate differs")
	}
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b.IPAddresses = nil
	b.EmailAddresses = nil
	b.URIs = nil
	b.Subject.CommonName = "changed.invalid"
	changed, err := x509.CreateCertificate(rand.Reader, &b, &b, &newKey.PublicKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	d, err = Compare(old, changed)
	if err != nil || d.SamePublicKey || !d.SubjectChanged || !d.IssuerChanged || len(d.RemovedNames) != 4 {
		t.Fatal("key or non-DNS names disappeared")
	}
}

func TestComparisonRefusesPrivateMixedBundlesAndMalformed(t *testing.T) {
	good, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, []byte("secret-marker"), []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"), append(append([]byte{}, good...), []byte("secret-marker")...), append(append([]byte{}, good...), good...), make([]byte, (96<<10)+1)} {
		if _, err := Compare(good, bad); err == nil {
			t.Fatal("forbidden candidate accepted")
		}
		if _, err := Compare(bad, good); err == nil {
			t.Fatal("forbidden saved side accepted")
		}
	}
	if ValidFingerprint("aa") || ValidFingerprint("AA:"+string(make([]byte, 92))) {
		t.Fatal("invalid identity")
	}
}

func FuzzPublicComparison(f *testing.F) {
	good, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good, good)
	f.Add([]byte("garbage"), []byte("PRIVATE KEY"))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		d, err := Compare(a, b)
		if err == nil && (!ValidFingerprint(d.OldFingerprint) || !ValidFingerprint(d.NewFingerprint) || d.Verification != "not-performed") {
			t.Fatal("comparison granted malformed identity or trust")
		}
	})
}
