package inventorystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmecertificate"
	"github.com/denyfirst/rootwell/internal/acmecertrequest"
	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func renewalFixture(t *testing.T) (key, id, closed, renewal []byte, fp string) {
	t.Helper()
	var done []byte
	key, id, _, done, _, fp, _ = syntheticCompletion(t)
	var err error
	closed, _, _, err = CloseStagingRequest(key, id, done, 13)
	if err != nil {
		t.Fatal(err)
	}
	renewal, _, _, err = BeginStagingRenewal(key, id, closed, 14, fp)
	if err != nil {
		t.Fatal("legitimate renewal refused", err)
	}
	return
}

func TestManualRenewalExactSourceIndependentKeyPairCompletionAndHistoricalDeletion(t *testing.T) {
	key, id, closed, image, fp := renewalFixture(t)
	defer clear(key)
	var oldHash [32]byte
	if err := WithCertificate(key, id, image, fp, 15, func(_ publicinventory.Record, private []byte) error { oldHash = sha256.Sum256(private); return nil }); err != nil {
		t.Fatal(err)
	}
	s, gen, err := ReadStagingOrder(key, id, image)
	if err != nil || gen != 15 || s.RenewalSource != fp || !slices.Equal(s.Domains, []string{"*.example.com", "example.com"}) {
		t.Fatal("renewal source/names not bound")
	}
	if next, _, err := DeleteRecord(key, id, image, fp, 15); !errors.Is(err, ErrRenewalSourceInUse) || next != nil {
		t.Fatal("active renewal lost original pair")
	}
	info := orderInstructionsFixture()
	info.URL = acmeorder.Origin + "/acme/order/1234/9999"
	image, _, gen, err = UpdateStagingOrder(key, id, image, 15, info.URL, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = UpdateStagingOrder(key, id, image, gen, "", &info, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = UpdateStagingOrder(key, id, image, gen, "", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = BeginStagingValidation(key, id, image, gen, false)
	if err != nil {
		t.Fatal(err)
	}
	result := acmeorder.Validation{URL: info.URL, Expires: info.Expires, OrderStatus: "ready", Statuses: []string{"valid", "valid"}}
	image, _, gen, err = FinishStagingValidation(key, id, image, gen, result)
	if err != nil {
		t.Fatal(err)
	}
	image, newKey, gen, err := PrepareStagingCertificateRequest(key, id, image, gen)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := decode(key, id, closed)
	if err != nil {
		t.Fatal(err)
	}
	_, _, oldIssuance, err := openClosedRequest(key, id, m, m.ClosedRequests[0])
	if err != nil || newKey.Fingerprint == oldIssuance.KeyFingerprint {
		t.Fatal("renewal reused original key")
	}
	assertRenewalReusedKeyRefused(t, key, id, image, closed, fp)
	image, _, _, gen, err = BeginStagingIssuance(key, id, image, gen, false)
	if err != nil {
		t.Fatal(err)
	}
	image, newFP, gen := completeRenewalFixture(t, key, id, image, gen)
	assertRenewalResult(t, key, id, image, gen, fp, newFP)
	if newFP == fp {
		t.Fatal("renewal overwrote original")
	}
	if records, g, err := Open(key, id, image); err != nil || g != gen || len(records) != 2 || records[0].StagingOrigin == nil || records[1].StagingOrigin == nil {
		t.Fatal("renewal failed to retain both checked pairs")
	}
	if err := WithCertificate(key, id, image, fp, gen, func(_ publicinventory.Record, private []byte) error {
		if sha256.Sum256(private) != oldHash {
			t.Fatal("old private key changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if next, _, err := DeleteRecord(key, id, image, fp, gen); !errors.Is(err, ErrRenewalSourceInUse) || next != nil {
		t.Fatal("completed active request discarded its source")
	}
	image, _, gen, err = CloseStagingRequest(key, id, image, gen)
	if err != nil {
		t.Fatal(err)
	}
	assertRenewalForwardSelfRefused(t, key, id, image, newFP)
	if result, g, err := ReadStagingRenewalResult(key, id, image, gen); err != nil || result != nil || g != gen {
		t.Fatal("closed renewal retained an active result")
	}
	image, gen, err = DeleteRecord(key, id, image, fp, gen)
	if err != nil {
		t.Fatal("closed renewal prevented explicit old deletion", err)
	}
	if records, g, err := Open(key, id, image); err != nil || g != gen || len(records) != 1 || records[0].Fingerprint != newFP {
		t.Fatal("source deletion lost renewal history/new pair")
	}
	image, gen, err = DeleteRecord(key, id, image, newFP, gen)
	if err != nil {
		t.Fatal(err)
	}
	if records, g, err := Open(key, id, image); err != nil || g != gen || len(records) != 0 {
		t.Fatal("historical renewal deletion invalidated image")
	}
	if source, g, err := ReadStagingRenewalSource(key, id, image, gen, newFP); err == nil || g != 0 || source.Fingerprint != "" {
		t.Fatal("deleted source regained renewal authority")
	}
	events, _, err := History(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Action == "acme-renewal-started" {
			found = true
			if !slices.Equal(event.Fingerprints, []string{fp}) {
				t.Fatal("renewal history lost source identity")
			}
		}
	}
	if !found {
		t.Fatal("renewal history absent")
	}
}

func assertRenewalForwardSelfRefused(t *testing.T, key, id, image []byte, newFP string) {
	t.Helper()
	m, _, err := decode(key, id, image)
	if err != nil || len(m.ClosedRequests) != 2 {
		t.Fatal("closed renewal fixture invalid")
	}
	for index := 0; index < 2; index++ {
		p, scope, _, err := openClosedRequest(key, id, m, m.ClosedRequests[index])
		if err != nil {
			t.Fatal(err)
		}
		order, err := openOrder(key, id, scope)
		if err != nil {
			t.Fatal(err)
		}
		order.RenewalSource = newFP // older -> future, then new -> itself
		plain, err := json.Marshal(order)
		if err != nil {
			t.Fatal(err)
		}
		k, err := orderKey(key, id)
		if err != nil {
			t.Fatal(err)
		}
		p.Orders = append([]sealedRecord{}, p.Orders...)
		p.Orders[0].Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, p.Orders[0]), plain)
		clear(k)
		clear(plain)
		if err != nil {
			t.Fatal(err)
		}
		bad := m
		bad.ClosedRequests = append([]sealedRecord{}, m.ClosedRequests...)
		if err := sealClosedRequest(key, id, &bad, index, p, order.URL); err != nil {
			t.Fatal(err)
		}
		encoded, err := encode(key, bad)
		if err != nil {
			t.Fatal(err)
		}
		if records, g, err := Open(key, id, encoded); err == nil || records != nil || g != 0 {
			t.Fatal("forward/self renewal reference exposed partial pairs")
		}
	}
}

func assertRenewalReusedKeyRefused(t *testing.T, key, id, image, closed []byte, fp string) {
	t.Helper()
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := decode(key, id, closed)
	if err != nil {
		t.Fatal(err)
	}
	_, scope, _, err := openClosedRequest(key, id, old, old.ClosedRequests[0])
	if err != nil {
		t.Fatal(err)
	}
	oldRequest, _, err := openCertificateRequest(key, id, scope)
	if err != nil {
		t.Fatal(err)
	}
	material, err := completionMaterial(key, id, old, fp)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.PrivateKey)
	request := requestPayloadFixture(t, key, id, m)
	clear(request.PrivateKey)
	request.PrivateKey = material.PrivateKey
	request.CSR = oldRequest.CSR
	plain, err := json.Marshal(request)
	defer clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	k, err := certificateRequestKey(key, id)
	defer clear(k)
	if err != nil {
		t.Fatal(err)
	}
	m.ACMECertificateRequests[0].Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, m.ACMECertificateRequests[0]), plain)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	if records, gen, err := Open(key, id, bad); err == nil || records != nil || gen != 0 {
		t.Fatal("valid reused key/CSR bypassed renewal rotation")
	}
}

// Synthetic checked completion only; no runtime trust override or real CA.
func completeRenewalFixture(t *testing.T, key, id, image []byte, gen uint64) ([]byte, string, uint64) {
	return completeRenewalWithLifetime(t, key, id, image, gen, time.Hour)
}

func completeRenewalWithLifetime(t *testing.T, key, id, image []byte, gen uint64, lifetime time.Duration) ([]byte, string, uint64) {
	t.Helper()
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	request := requestPayloadFixture(t, key, id, m)
	defer clear(request.PrivateKey)
	csr, err := x509.ParseCertificateRequest(request.CSR)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rt := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "synthetic renewal root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(24 * time.Hour)}
	rd, err := x509.CreateCertificate(rand.Reader, rt, rt, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rd)
	if err != nil {
		t.Fatal(err)
	}
	lt := &x509.Certificate{SerialNumber: big.NewInt(12), DNSNames: slices.Clone(request.Names), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: at.Add(-time.Minute), NotAfter: at.Add(lifetime)}
	ld, err := x509.CreateCertificate(rand.Reader, lt, root, csr.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	checker := func(private, csr []byte, names []string, response [][]byte, now time.Time) (acmecertificate.Result, error) {
		summary, err := acmecertrequest.Check(private, csr, names)
		if err != nil {
			return acmecertificate.Result{}, err
		}
		leaf, err := x509.ParseCertificate(response[0])
		if err != nil {
			return acmecertificate.Result{}, err
		}
		roots := x509.NewCertPool()
		roots.AddCert(root)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return acmecertificate.Result{}, err
		}
		return acmecertificate.Result{TestOnly: true, Fingerprint: certificateFingerprint(ld), PublicFingerprint: summary.PublicFingerprint, RequestFingerprint: summary.RequestFingerprint, DNSNames: slices.Clone(names), EvaluatedAt: now, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, ChainFingerprints: []string{certificateFingerprint(ld), certificateFingerprint(rd)}}, nil
	}
	next, s, g, err := finishStagingIssuance(key, id, image, gen, [][]byte{ld, rd}, at, checker)
	if err != nil || s.State != "certificate-saved" {
		t.Fatal("renewal checked completion refused", err)
	}
	return next, certificateFingerprint(ld), g
}

func TestManualRenewalRefusesStaleOrphanActiveDeletedNamesAndTamperedLinks(t *testing.T) {
	key, id, closed, image, fp := renewalFixture(t)
	defer clear(key)
	before := slices.Clone(closed)
	otherFP := "A" + fp[1:]
	if fp[0] == 'A' {
		otherFP = "B" + fp[1:]
	}
	for _, tc := range []struct {
		image []byte
		gen   uint64
		fp    string
	}{{closed, 13, fp}, {image, 15, fp}, {closed, 14, ""}, {closed, 14, "malformed"}, {closed, 14, otherFP}} {
		if next, _, g, err := BeginStagingRenewal(key, id, tc.image, tc.gen, tc.fp); err == nil || next != nil || g != 0 {
			t.Fatal("invalid renewal gained intent")
		}
	}
	deleted, _, err := DeleteRecord(key, id, closed, fp, 14)
	if err != nil {
		t.Fatal(err)
	}
	if next, _, g, err := BeginStagingRenewal(key, id, deleted, 15, fp); err == nil || next != nil || g != 0 {
		t.Fatal("deleted source renewed")
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	p, err := openOrder(key, id, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*orderPayload){func(p *orderPayload) { p.RenewalSource = otherFP }, func(p *orderPayload) { p.Domains = []string{"other.example.com"} }, func(p *orderPayload) { p.Started = "2020-01-01T00:00:00Z" }} {
		bad := m
		bad.ACMEOrders = append([]sealedRecord{}, m.ACMEOrders...)
		changed := p
		mutate(&changed)
		plain, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		k, err := orderKey(key, id)
		if err != nil {
			t.Fatal(err)
		}
		bad.ACMEOrders[0].Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, bad.ACMEOrders[0]), plain)
		clear(k)
		clear(plain)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := encode(key, bad)
		if err != nil {
			t.Fatal(err)
		}
		if records, g, err := Open(key, id, encoded); err == nil || records != nil || g != 0 {
			t.Fatal("tampered renewal exposed partial source")
		}
		if result, g, err := ReadStagingRenewalResult(key, id, encoded, 15); err == nil || result != nil || g != 0 {
			t.Fatal("valid-MAC tampered renewal exposed partial comparison")
		}
	}
	if !bytes.Equal(before, closed) {
		t.Fatal("refusal mutated original image")
	}
}

func FuzzRenewalOrderBinding(f *testing.F) {
	f.Add([]byte(`null`))
	f.Add([]byte(`{"renewal_source":"not-a-source"}`))
	var once sync.Once
	var key, id []byte
	var m manifest
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) == 0 || len(raw) > 16384-64 {
			return
		}
		once.Do(func() { var image []byte; key, id, _, image, _ = renewalFixture(t); m, _, _ = decode(key, id, image) })
		bad := m
		bad.ACMEOrders = append([]sealedRecord{}, m.ACMEOrders...)
		k, err := orderKey(key, id)
		if err != nil {
			t.Fatal(err)
		}
		bad.ACMEOrders[0].Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, bad.ACMEOrders[0]), raw)
		clear(k)
		if err != nil {
			t.Fatal(err)
		}
		image, err := encode(key, bad)
		if err != nil {
			t.Fatal(err)
		}
		if records, g, err := Open(key, id, image); err != nil && (records != nil || g != 0) {
			t.Fatal("fuzzed renewal exposed partial records")
		}
	})
}

func TestRenewalDeletionGenerationRemainsStrictAtEqualTimes(t *testing.T) {
	fp := "AB:" + strings.Repeat("CD:", 30) + "EF"
	at := "2026-10-13T00:00:00Z"
	order := orderPayload{RenewalSource: fp, Fingerprint: "account", Domains: []string{"example.com"}, Started: at}
	for _, deletedGen := range []uint64{14, 24, 25} {
		anchors := map[string]renewalAnchor{fp: {Account: "account", Names: []string{"example.com"}, Key: "original-key", ClosedAt: at, ClosedGeneration: 13, DeletedAt: at, DeletedGeneration: deletedGen}}
		err := checkRenewalBinding(order, 20, at, 24, "new-key", anchors)
		if (err == nil) != (deletedGen > 24) {
			t.Fatal("equal timestamps erased deletion generation ordering")
		}
		if err := checkRenewalBinding(order, 20, "", 0, "new-key", anchors); err == nil {
			t.Fatal("deleted active source gained authority")
		}
	}
}
