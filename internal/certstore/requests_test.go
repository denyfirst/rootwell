package certstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/csrworkbench"
	"github.com/denyfirst/rootwell/internal/publicinventory"
	"github.com/denyfirst/rootwell/internal/vault"
)

// request makes a request whose key Rootwell would keep.
func request(t *testing.T, names ...string) (csr, key []byte) {
	t.Helper()
	csr, key, _, err := csrworkbench.GenerateKept("ec-p256", csrworkbench.Params{DNSNames: names})
	if err != nil {
		t.Fatal(err)
	}
	return csr, key
}

// issueFor signs a leaf for a request's key, as a provider would, for names
// and lasting life from an hour ago.
func issueFor(t *testing.T, csr []byte, life time.Duration, names ...string) issued {
	t.Helper()
	block, _ := pem.Decode(csr)
	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return issueKey(t, parsed.PublicKey, nil, life, names...)
}

// issueKey signs a leaf for a public key under a fresh issuer. key, when set,
// is the private key's PKCS #8 PEM, kept with the result.
func issueKey(t *testing.T, public any, key []byte, life time.Duration, names ...string) issued {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0] + " issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(life + time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(life), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	records, err := certificatepair.Analyze(leaf, nil, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("fingerprint: %v", err)
	}
	return issued{certificate: append(leaf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...),
		key: key, fingerprint: records[0].Fingerprint}
}

func find(records []publicinventory.Record, fingerprint string) publicinventory.Record {
	for _, r := range records {
		if r.Fingerprint == fingerprint {
			return r
		}
	}
	return publicinventory.Record{}
}

func TestARequestKeepsItsKeyUntilItsCertificateFinishesIt(t *testing.T) {
	s, _ := newStore(t)
	csr, key := request(t, "shop.example")
	defer clear(key)
	q, generation, err := s.AddRequest(1, csr, key, "")
	if err != nil || generation != 2 {
		t.Fatalf("add a request: %v at %d", err, generation)
	}
	if !bytes.Equal(q.CSR, csr) || !slices.Equal(q.DNSNames, []string{"shop.example"}) || q.KeyType != "ECDSA P-256" || q.Renews != "" {
		t.Fatalf("the request reads back as %+v", q)
	}
	records, waiting, at, err := s.ListAll()
	if err != nil || len(records) != 0 || len(waiting) != 1 || at != 2 || waiting[0].PublicFingerprint != q.PublicFingerprint {
		t.Fatalf("list: %d certificates, %d requests at %d: %v", len(records), len(waiting), at, err)
	}
	listed, _ := json.Marshal(waiting)
	if bytes.Contains(listed, key) || bytes.Contains(listed, []byte("PRIVATE")) {
		t.Fatal("the list of requests carries the key")
	}

	// The provider's certificate for that key comes back without one.
	c := issueFor(t, csr, 90*24*time.Hour, "shop.example")
	check, _ := certificatepair.Analyze(c.certificate, nil, nil)
	plan, err := s.Successor(check[0])
	if err != nil || !plan.Finishes || plan.Replaces != "" || plan.Renews != "" {
		t.Fatalf("before saving: %+v: %v", plan, err)
	}
	saved, generation, err := s.Save(2, c.certificate, nil, nil, "", "", c.fingerprint, false, "")
	if err != nil || generation != 3 || !saved.HasPrivateKey || saved.KeyStatus != "matched" {
		t.Fatalf("save the certificate: %+v at %d: %v", saved, generation, err)
	}
	records, waiting, _, err = s.ListAll()
	if err != nil || len(records) != 1 || len(waiting) != 0 {
		t.Fatalf("after saving: %d certificates, %d requests: %v", len(records), len(waiting), err)
	}
	var lent []byte
	if err := s.WithCertificate(3, c.fingerprint, func(_ publicinventory.Record, k []byte) error { lent = bytes.Clone(k); return nil }); err != nil {
		t.Fatal(err)
	}
	keptKey, _ := x509.ParsePKCS8PrivateKey(key)
	lentKey, err := x509.ParsePKCS8PrivateKey(lent)
	if err != nil || !keptKey.(*ecdsa.PrivateKey).Equal(lentKey) {
		t.Fatalf("the saved key is not the request's own: %v", err)
	}
	// A certificate for another key finishes nothing.
	other := issue(t, "shop.example")
	check, _ = certificatepair.Analyze(other.certificate, nil, nil)
	if plan, err := s.Successor(check[0]); err != nil || plan.Finishes {
		t.Fatalf("another key finishes a request: %+v %v", plan, err)
	}
}

func TestARenewalTakesTheOlderCertificatesPlace(t *testing.T) {
	s, _ := newStore(t)
	old := issue(t, "a.example")
	if _, _, err := s.Save(1, old.certificate, old.key, nil, "Platform team", "web-1", old.fingerprint, false, ""); err != nil {
		t.Fatal(err)
	}
	csr, key := request(t, "a.example")
	defer clear(key)
	q, g, err := s.AddRequest(2, csr, key, old.fingerprint)
	if err != nil || q.Renews != old.fingerprint {
		t.Fatalf("renew: %+v: %v", q, err)
	}
	again, againKey := request(t, "a.example")
	defer clear(againKey)
	if _, _, err := s.AddRequest(g, again, againKey, old.fingerprint); !errors.Is(err, ErrRenewalWaiting) {
		t.Fatalf("a second renewal of one certificate: %v", err)
	}
	if _, _, err := s.AddRequest(g, again, againKey, issue(t, "x.example").fingerprint); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a renewal of a certificate not saved: %v", err)
	}

	renewed := issueFor(t, csr, 90*24*time.Hour, "a.example")
	check, _ := certificatepair.Analyze(renewed.certificate, nil, nil)
	if plan, err := s.Successor(check[0]); err != nil || !plan.Finishes || plan.Renews != old.fingerprint || plan.Replaces != "" {
		t.Fatalf("before saving: %+v: %v", plan, err)
	}
	saved, g, err := s.Save(g, renewed.certificate, nil, nil, "", "web-2", renewed.fingerprint, false, "")
	if err != nil || saved.Replaces != old.fingerprint {
		t.Fatalf("save the renewal: %+v: %v", saved, err)
	}
	records, _, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	now, before := find(records, renewed.fingerprint), find(records, old.fingerprint)
	if now.Owner != "Platform team" || !slices.Equal(now.Locations, []string{"web-1", "web-2"}) || now.Replaces != old.fingerprint || now.ReplacedBy != "" {
		t.Fatalf("the renewal did not take the older one's place: %+v", now)
	}
	if before.ReplacedBy != renewed.fingerprint || before.ReplacedAt == "" || !before.HasPrivateKey {
		t.Fatalf("the older one is not marked replaced, or lost its key: %+v", before)
	}
	if _, _, err := s.AddRequest(g, again, againKey, old.fingerprint); !errors.Is(err, ErrReplaced) {
		t.Fatalf("a renewal of a replaced certificate: %v", err)
	}
	// Deleting the renewal brings the older one back.
	if _, err = s.Delete(g, renewed.fingerprint, true); err != nil {
		t.Fatal(err)
	}
	records, _, _ = s.List()
	if back := find(records, old.fingerprint); back.ReplacedBy != "" || back.ReplacedAt != "" {
		t.Fatalf("the older one stays replaced by a deleted certificate: %+v", back)
	}
}

func TestAChosenReplacementMustCoverTheNamesAndLastLonger(t *testing.T) {
	s, _ := newStore(t)
	old := issue(t, "a.example") // 24 hours
	_, g, err := s.Save(1, old.certificate, nil, nil, "Ops", "", old.fingerprint, false, "")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, tc := range []struct {
		name  string
		names []string
		life  time.Duration
	}{
		{"ends sooner", []string{"a.example"}, 12 * time.Hour},
		{"misses a name", []string{"b.example"}, 48 * time.Hour},
	} {
		c := issueKey(t, &key.PublicKey, nil, tc.life, tc.names...)
		check, _ := certificatepair.Analyze(c.certificate, nil, nil)
		if plan, err := s.Successor(check[0]); err != nil || plan.Replaces != "" {
			t.Fatalf("%s: offered to replace: %+v: %v", tc.name, plan, err)
		}
		if _, _, err := s.Save(g, c.certificate, nil, nil, "", "", c.fingerprint, false, old.fingerprint); !errors.Is(err, ErrCannotReplace) {
			t.Fatalf("%s: replaced: %v", tc.name, err)
		}
	}
	if records, at, _ := s.List(); len(records) != 1 || at != g {
		t.Fatalf("a refused replacement saved something: %d at %d", len(records), at)
	}
	// An authority works for no names, so nothing takes its place.
	authority := bytes.SplitAfter(old.certificate, []byte("-----END CERTIFICATE-----\n"))[1]
	analysed, _ := certificatepair.Analyze(authority, nil, nil)
	if _, g, err = s.Save(g, authority, nil, nil, "", "", analysed[0].Fingerprint, false, ""); err != nil {
		t.Fatal(err)
	}
	wide := issueKey(t, &key.PublicKey, nil, 48*time.Hour, "a.example", "www.a.example")
	if _, _, err := s.Save(g, wide.certificate, nil, nil, "", "", wide.fingerprint, false, analysed[0].Fingerprint); !errors.Is(err, ErrCannotReplace) {
		t.Fatalf("a certificate replaced an authority: %v", err)
	}
	check, _ := certificatepair.Analyze(wide.certificate, nil, nil)
	if plan, err := s.Successor(check[0]); err != nil || plan.Replaces != old.fingerprint || plan.Finishes {
		t.Fatalf("the newer one is not offered to replace the older: %+v %v", plan, err)
	}
	saved, g, err := s.Save(g, wide.certificate, nil, nil, "", "", wide.fingerprint, false, old.fingerprint)
	if err != nil || saved.Replaces != old.fingerprint || saved.Owner != "Ops" {
		t.Fatalf("the chosen replacement: %+v: %v", saved, err)
	}
	third := issueKey(t, &key.PublicKey, nil, 72*time.Hour, "a.example")
	if _, _, err := s.Save(g, third.certificate, nil, nil, "", "", third.fingerprint, false, old.fingerprint); !errors.Is(err, ErrCannotReplace) {
		t.Fatalf("a replaced certificate was replaced again: %v", err)
	}
}

func TestARequestNeedsItsOwnKeyAndGivingItUpDeletesTheKey(t *testing.T) {
	s, v := newStore(t)
	csr, key := request(t, "shop.example")
	_, otherKey := request(t, "shop.example")
	defer clear(key)
	defer clear(otherKey)
	if _, _, err := s.AddRequest(1, csr, otherKey, ""); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a request was kept with another key: %v", err)
	}
	broken := bytes.Replace(csr, []byte("REQUEST-----\n"), []byte("REQUEST-----\nX"), 1)
	if _, _, err := s.AddRequest(1, broken, key, ""); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a broken request was kept: %v", err)
	}
	q, g, err := s.AddRequest(1, csr, key, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AddRequest(g, csr, key, ""); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("one key was kept twice: %v", err)
	}
	if _, err := s.DeleteRequest(1, q.PublicFingerprint); !errors.Is(err, ErrStale) {
		t.Fatalf("a stale page gave up a request: %v", err)
	}
	if g, err = s.DeleteRequest(g, q.PublicFingerprint); err != nil {
		t.Fatal(err)
	}
	if _, waiting, _, _ := s.ListAll(); len(waiting) != 0 {
		t.Fatal("the request is still waiting")
	}
	if err := v.View(func(t *vault.Tx) error {
		if _, _, err := t.Get(kindRequestKey, v.Index(kindRequest, q.PublicFingerprint)); !errors.Is(err, vault.ErrMissing) {
			return errors.New("the key outlived its request")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteRequest(g, q.PublicFingerprint); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("a request was given up twice: %v", err)
	}
	for i := 0; i < MaxRequests; i++ {
		more, moreKey := request(t, "shop.example")
		if _, g, err = s.AddRequest(g, more, moreKey, ""); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		clear(moreKey)
	}
	last, lastKey := request(t, "shop.example")
	defer clear(lastKey)
	if _, _, err := s.AddRequest(g, last, lastKey, ""); !errors.Is(err, ErrRequestsFull) {
		t.Fatalf("request %d was kept: %v", MaxRequests+1, err)
	}
}

func TestARequestRecordIsReadStrictly(t *testing.T) {
	s, v := newStore(t)
	csr, key := request(t, "shop.example")
	defer clear(key)
	q, _, err := s.AddRequest(1, csr, key, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Update(func(t *vault.Tx) error {
		id := v.Index(kindRequest, q.PublicFingerprint)
		plain, _, err := t.Get(kindRequest, id)
		if err != nil {
			return err
		}
		var fields map[string]any
		if err := json.Unmarshal(plain, &fields); err != nil {
			return err
		}
		fields["key"] = "smuggled"
		changed, _ := json.Marshal(fields)
		return t.Put(kindRequest, id, changed)
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.ListAll(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a request record with an unknown field was listed: %v", err)
	}
}

// Certificates last shorter every year: a renewal made early may end before
// the certificate it renews, and still takes its place.
func TestAnEarlyRenewalThatEndsSoonerStillTakesThePlace(t *testing.T) {
	s, _ := newStore(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	old := issueKey(t, &key.PublicKey, nil, 300*24*time.Hour, "long.example")
	_, g, err := s.Save(1, old.certificate, nil, nil, "Ops", "edge-1", old.fingerprint, false, "")
	if err != nil {
		t.Fatal(err)
	}
	csr, requestKey := request(t, "long.example")
	defer clear(requestKey)
	if _, g, err = s.AddRequest(g, csr, requestKey, old.fingerprint); err != nil {
		t.Fatal(err)
	}
	renewed := issueFor(t, csr, 100*24*time.Hour, "long.example")
	check, _ := certificatepair.Analyze(renewed.certificate, nil, nil)
	if plan, err := s.Successor(check[0]); err != nil || plan.Renews != old.fingerprint {
		t.Fatalf("a shorter renewal is not offered as the renewal: %+v %v", plan, err)
	}
	saved, _, err := s.Save(g, renewed.certificate, nil, nil, "", "", renewed.fingerprint, false, "")
	if err != nil || saved.Replaces != old.fingerprint || saved.Owner != "Ops" || !slices.Equal(saved.Locations, []string{"edge-1"}) {
		t.Fatalf("a shorter renewal did not take the place: %+v %v", saved, err)
	}
}
