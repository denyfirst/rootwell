package inventorystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmecertificate"
	"github.com/denyfirst/rootwell/internal/acmecertrequest"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func syntheticCompletion(t *testing.T) (key, id, pending, completed []byte, chain [][]byte, fp string, at time.Time) {
	t.Helper()
	key, id, pending = issuanceFixture(t)
	pending, _, _, _, err := BeginStagingIssuance(key, id, pending, 11, false)
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := decode(key, id, pending)
	request := requestPayloadFixture(t, key, id, m)
	defer clear(request.PrivateKey)
	at = time.Now().UTC().Truncate(time.Second)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic completion test root"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 1}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(request.CSR)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: slices.Clone(request.Names), NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, csr.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	chain = [][]byte{leafDER, rootDER}
	fp = certificateFingerprint(leafDER)
	// Synthetic custody success seam verifies its independent synthetic path.
	// Production Finish (below) MUST still reject this unpinned root.
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
		return acmecertificate.Result{TestOnly: true, Fingerprint: certificateFingerprint(response[0]), PublicFingerprint: summary.PublicFingerprint, RequestFingerprint: summary.RequestFingerprint, DNSNames: slices.Clone(names), EvaluatedAt: now, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, ChainFingerprints: []string{certificateFingerprint(response[0]), certificateFingerprint(rootDER)}}, nil
	}
	completed, s, g, err := finishStagingIssuance(key, id, pending, 12, chain, at, checker)
	if err != nil || g != 13 || s.State != "certificate-saved" {
		t.Fatal("valid checked pair completion refused")
	}
	return
}

func TestCompletionAtomicMoveProvenanceNotesExportDeleteAndNoReplay(t *testing.T) {
	key, id, pending, done, chain, fp, _ := syntheticCompletion(t)
	before, _, _ := decode(key, id, pending)
	original := requestPayloadFixture(t, key, id, before)
	defer clear(original.PrivateKey)
	m, records, err := decode(key, id, done)
	if err != nil || len(records) != 1 || !records[0].HasPrivateKey || records[0].KeyStatus != "matched" || records[0].StagingOrigin == nil || !records[0].StagingOrigin.TestOnly || records[0].StagingOrigin.Provider != "letsencrypt-staging" || records[0].Fingerprint != fp || len(records[0].BundleDER) != 2 {
		t.Fatal("complete pair or staging provenance missing")
	}
	transferred := requestPayloadFixture(t, key, id, m)
	if transferred.State != "key-transferred" || len(transferred.PrivateKey) != 0 || !bytes.Equal(transferred.CSR, original.CSR) || transferred.CertificateFingerprint != fp || !bytes.Equal(before.ACMEAccounts[0].Ciphertext, m.ACMEAccounts[0].Ciphertext) || !bytes.Equal(before.ACMEOrders[0].Ciphertext, m.ACMEOrders[0].Ciphertext) {
		t.Fatal("key not moved or account/order/CSR changed")
	}
	material, err := completionMaterial(key, id, m, fp)
	defer clear(material.PrivateKey)
	if err != nil || !bytes.Equal(material.PrivateKey, original.PrivateKey) {
		t.Fatal("exact prepared key not transferred")
	}
	public, _ := json.Marshal(records[0].StagingOrigin)
	if bytes.Contains(done, original.PrivateKey) || bytes.Contains(public, []byte("csr")) || bytes.Contains(public, []byte("order")) {
		t.Fatal("secret/internal origin leak")
	}
	if _, _, _, err := FinishStagingIssuance(key, id, pending, 12, chain); err != acmecertificate.ErrInvalid {
		t.Fatal("production accepted unpinned synthetic CA")
	}
	if _, _, _, err := FinishStagingIssuance(key, id, done, 13, chain); err == nil {
		t.Fatal("completed pair replayed")
	}
	for _, readOnly := range []bool{false, true} {
		if out, token, _, _, err := BeginStagingIssuance(key, id, done, 13, readOnly); err == nil || out != nil || token != nil {
			t.Fatal("completion regained network lease")
		}
	}
	if _, _, _, err := ObserveStagingIssuance(key, id, done, 13, "processing"); err == nil {
		t.Fatal("completion overwritten by observation")
	}
	if _, _, _, err := PrepareStagingCertificateRequest(key, id, done, 13); err == nil {
		t.Fatal("completed key regenerated")
	}
	noted, r, g, err := UpdateOwner(key, id, done, fp, "test owner", 13)
	if err != nil || g != 14 || r.StagingOrigin == nil {
		t.Fatal("metadata lost immutable origin")
	}
	reread, _, err := Open(key, id, noted)
	if err != nil || !reflect.DeepEqual(reread[0].StagingOrigin, records[0].StagingOrigin) {
		t.Fatal("note changed origin")
	}
	if err := WithCertificate(key, id, noted, fp, 14, func(r publicinventory.Record, private []byte) error {
		if !bytes.Equal(private, original.PrivateKey) || r.StagingOrigin == nil {
			return errors.New("lost paired key or origin")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	deleted, g, err := DeleteRecord(key, id, noted, fp, 14)
	if err != nil || g != 15 {
		t.Fatal("paired deletion refused")
	}
	m, records, err = decode(key, id, deleted)
	if err != nil || len(records) != 0 || len(m.Materials) != 0 || len(m.ACMECertificateRequests) != 0 {
		t.Fatal("delete retained current key/CSR or orphaned origin")
	}
	s, g, err := ReadStagingIssuance(key, id, deleted)
	if err != nil || g != 15 || s.State != "saved-certificate-deleted" {
		t.Fatal("deletion erased no-replay tombstone")
	}
	if _, _, _, err := PrepareStagingCertificateRequest(key, id, deleted, 15); err == nil {
		t.Fatal("delete allowed same-order key regeneration")
	}
	// Original backup/image retains the complete pair. Deletion is not erasure.
	if records, _, err := Open(key, id, done); err != nil || len(records) != 1 || !records[0].HasPrivateKey {
		t.Fatal("deletion mutated old snapshot")
	}
	events, _, _ := History(key, id, done)
	if events[len(events)-1].Action != "acme-certificate-saved" {
		t.Fatal("completion history lost")
	}
}

func TestCompletionWholeImageTamperRefusesBeforePublicOutput(t *testing.T) {
	key, id, _, done, _, _, _ := syntheticCompletion(t)
	m, _, _ := decode(key, id, done)
	p, _ := openIssuance(key, id, m)
	for _, change := range []func(*issuancePayload){func(p *issuancePayload) { p.Completion.TestOnly = false }, func(p *issuancePayload) { p.Completion.Fingerprint = p.KeyFingerprint }, func(p *issuancePayload) { p.Completion.Generation = 12 }, func(p *issuancePayload) { p.Completion.SavedAt = "2020-01-01T00:00:00Z" }, func(p *issuancePayload) { p.Completion.ChainFingerprints[0] = p.KeyFingerprint }, func(p *issuancePayload) { p.Completion.DeletedAt = p.Completion.SavedAt }, func(p *issuancePayload) { p.RequestFingerprint = "" }, func(p *issuancePayload) { p.Observation = "valid" }} {
		copyP := p
		copyC := *p.Completion
		copyC.ChainFingerprints = slices.Clone(p.Completion.ChainFingerprints)
		copyP.Completion = &copyC
		change(&copyP)
		raw, _ := json.Marshal(copyP)
		bad := issuanceRawImage(t, key, id, m, raw)
		if records, g, err := Open(key, id, bad); err == nil || records != nil || g != 0 {
			t.Fatal("forged completion exposed partial public data")
		}
	}
	for _, change := range []func(*manifest){func(m *manifest) { m.Materials = nil }, func(m *manifest) { m.ACMEIssuances = nil }, func(m *manifest) { m.ACMECertificateRequests = nil }, func(m *manifest) { m.Records = nil }} {
		copyM := m
		change(&copyM)
		bad, err := encode(key, copyM)
		if err != nil {
			t.Fatal(err)
		}
		if records, g, err := Open(key, id, bad); err == nil || records != nil || g != 0 {
			t.Fatal("orphaned completion accepted")
		}
	}
}

func TestCompletionRefusalsAndReservedFinalGenerationHistorySlot(t *testing.T) {
	key, id, pending, done, chain, _, at := syntheticCompletion(t)
	completed, _, _ := decode(key, id, done)
	accepted, _ := openIssuance(key, id, completed)
	checker := func(private, csr []byte, names []string, response [][]byte, when time.Time) (acmecertificate.Result, error) {
		summary, err := acmecertrequest.Check(private, csr, names)
		if err != nil {
			return acmecertificate.Result{}, err
		}
		leaf, err := x509.ParseCertificate(response[0])
		if err != nil {
			return acmecertificate.Result{}, err
		}
		return acmecertificate.Result{TestOnly: true, Fingerprint: certificateFingerprint(response[0]), PublicFingerprint: summary.PublicFingerprint, RequestFingerprint: summary.RequestFingerprint, DNSNames: slices.Clone(names), EvaluatedAt: when, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, ChainFingerprints: slices.Clone(accepted.Completion.ChainFingerprints)}, nil
	}
	for _, tc := range []struct {
		g        uint64
		at       time.Time
		response [][]byte
	}{{11, at, chain}, {12, at.Add(-24 * time.Hour), chain}, {12, at.Add(24 * time.Hour), chain}, {12, at, nil}, {12, at, append(append([][]byte{}, chain...), chain...)}} {
		out, s, g, err := finishStagingIssuance(key, id, pending, tc.g, tc.response, tc.at, checker)
		if err == nil || out != nil || g != 0 || s.State != "" {
			t.Fatal("unsafe completion returned partial pair")
		}
	}
	for _, mutate := range []func(*acmecertificate.Result){func(r *acmecertificate.Result) { r.TestOnly = false }, func(r *acmecertificate.Result) { r.PublicFingerprint = "" }, func(r *acmecertificate.Result) { r.RequestFingerprint = "" }, func(r *acmecertificate.Result) { r.DNSNames = []string{"wrong.example.com"} }, func(r *acmecertificate.Result) { r.EvaluatedAt = r.EvaluatedAt.Add(time.Hour) }} {
		liar := func(private, csr []byte, names []string, response [][]byte, when time.Time) (acmecertificate.Result, error) {
			r, err := checker(private, csr, names, response, when)
			mutate(&r)
			return r, err
		}
		if out, s, g, err := finishStagingIssuance(key, id, pending, 12, chain, at, liar); err == nil || out != nil || g != 0 || s.State != "" {
			t.Fatal("forged check result manufactured custody")
		}
	}
	duplicate, _, err := Append(key, id, pending, chain[0], "", "original notes")
	if err != nil {
		t.Fatal(err)
	}
	if out, _, _, err := finishStagingIssuance(key, id, duplicate, 13, chain, at, checker); err != publicinventory.ErrDuplicate || out != nil {
		t.Fatal("completion overwrote an existing certificate")
	}
	// Consume exactly the reserved final generation AND history event. Historical
	// fixtures deliberately start later, like a legacy image without early events.
	m, _, _ := decode(key, id, pending)
	m.Generation = maxGeneration - 1
	m.History = nil
	for gen := maxGeneration - maxHistory + 1; gen < maxGeneration; gen++ {
		event := Event{Generation: uint64(gen), At: at.Format("2006-01-02T15:04:05Z"), Action: "owner-changed", Fingerprints: []string{accepted.KeyFingerprint}}
		raw, _ := json.Marshal(event)
		sealed, err := inventoryseal.Seal(key, eventContext(id, uint64(gen)), raw)
		if err != nil {
			t.Fatal(err)
		}
		m.History = append(m.History, sealedRecord{Generation: uint64(gen), Ciphertext: sealed})
	}
	image, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	final, s, g, err := finishStagingIssuance(key, id, image, maxGeneration-1, chain, at, checker)
	if err != nil || final == nil || g != maxGeneration || s.State != "certificate-saved" {
		t.Fatal("reserved completion slot unusable")
	}
	if records, gen, err := Open(key, id, final); err != nil || gen != maxGeneration || len(records) != 1 || !records[0].HasPrivateKey {
		t.Fatal("final-slot pair not readable")
	}
	events, gen, err := History(key, id, final)
	if err != nil || gen != maxGeneration || len(events) != maxHistory || events[len(events)-1].Action != "acme-certificate-saved" {
		t.Fatal("final completion history lost")
	}
}

// Child helper for Linux restore tests: runtime-only encrypted synthetic image
// and test data key go to a private temp file, never stdout/repo/CI artifacts.
func TestGenerateSyntheticCompletionForIntegration(t *testing.T) {
	path := os.Getenv("ROOTWELL_TEST_COMPLETION_FIXTURE")
	if path == "" {
		t.Skip("private integration fixture not requested")
	}
	if !filepath.IsAbs(path) || filepath.Base(path) != "synthetic-completion.json" {
		t.Fatal("fixture destination refused")
	}
	key, id, pending, done, chain, fp, _ := syntheticCompletion(t)
	defer clear(key)
	body, err := json.Marshal(struct {
		Key, ID, Image, Pending []byte
		Chain                   [][]byte
		Fingerprint             string
	}{key, id, done, pending, chain, fp})
	defer clear(body)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal("private fixture creation refused")
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		t.Fatal("private fixture write refused")
	}
}

func FuzzStagingCompletionPayload(f *testing.F) {
	f.Add([]byte(`{"completion":{"test_only":false}}`))
	f.Add([]byte(`null`))
	var once sync.Once
	var key, id []byte
	var m manifest
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 || len(raw) == 0 {
			return
		}
		once.Do(func() {
			var done []byte
			key, id, _, done, _, _, _ = syntheticCompletion(t)
			m, _, _ = decode(key, id, done)
		})
		bad := issuanceRawImage(t, key, id, m, raw)
		records, g, err := Open(key, id, bad)
		if err != nil && (records != nil || g != 0) {
			t.Fatal("fuzzed completion returned partial custody")
		}
	})
}
