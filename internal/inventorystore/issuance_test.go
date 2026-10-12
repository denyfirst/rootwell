package inventorystore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmecertrequest"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/keymatch"
)

func issuanceFixture(t *testing.T) (key, id, image []byte) {
	t.Helper()
	key, id, image = verifiedCertificateRequestFixture(t)
	image, _, _, err := PrepareStagingCertificateRequest(key, id, image, 10)
	if err != nil {
		t.Fatal(err)
	}
	return key, id, image
}

func TestIssuanceDeadlineOnlyNarrowsAndSurvivesReopen(t *testing.T) {
	key, id, image := issuanceFixture(t)
	defer clear(key)
	image, _, _, gen, err := BeginStagingIssuance(key, id, image, 11, false)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(time.Minute).Format("2006-01-02T15:04:05Z")
	bounded, err := ConstrainStagingIssuance(key, id, image, gen, deadline)
	if err != nil {
		t.Fatal("shortened expiry refused")
	}
	s, g, err := ReadStagingIssuance(key, id, bounded)
	if err != nil || g != 12 || s.Expires != deadline {
		t.Fatal("deadline not authenticated")
	}
	for _, bad := range []string{"", "2020-01-01T00:00:00Z", "9999-01-01T00:00:00Z", time.Now().UTC().Add(2 * time.Minute).Format("2006-01-02T15:04:05Z")} {
		if next, err := ConstrainStagingIssuance(key, id, bounded, 12, bad); err == nil || next != nil {
			t.Fatal("deadline extended or malformed constraint accepted")
		}
	}
	next, s, g, err := ObserveStagingIssuance(key, id, bounded, 12, "processing")
	if err != nil || g != 13 || s.Expires != deadline {
		t.Fatal("observation lost narrowed deadline")
	}
	_, attempt, _, _, err := BeginStagingIssuance(key, id, next, 13, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := WithStagingIssuance(key, id, next, 13, attempt, func(_ crypto.Signer, _, _, expires string, _ []string, _, _ []byte, readOnly bool) error {
		if !readOnly || expires != deadline {
			t.Fatal("reopened lease extended provider expiry")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	at, _ := time.Parse("2006-01-02T15:04:05Z", deadline)
	if _, attempt, s, g, err := beginStagingIssuanceAt(key, id, next, 13, true, at); err == nil || attempt != nil || s.State != "" || g != 0 {
		t.Fatal("expired narrowed authority reacquired")
	}
	// Historical observation is still readable after expiry, not authorization.
	if _, _, err := ReadStagingIssuance(key, id, next); err != nil {
		t.Fatal("expiry made authenticated custody unreadable")
	}
}

func TestIssuanceIntentExactScopeEncryptionAndSingleUseReadOnlyRecovery(t *testing.T) {
	key, id, image := issuanceFixture(t)
	before, _, _ := decode(key, id, image)
	next, attempt, status, gen, err := BeginStagingIssuance(key, id, image, 11, false)
	if err != nil || gen != 12 || status.State != "issuance-pending" || status.StartedAt == "" || status.CheckedAt != "" || status.Observation != "" {
		t.Fatal("valid issuance intent refused")
	}
	after, _, _ := decode(key, id, next)
	for _, pair := range [][2][]byte{{before.ACMEAccounts[0].Ciphertext, after.ACMEAccounts[0].Ciphertext}, {before.ACMEOrders[0].Ciphertext, after.ACMEOrders[0].Ciphertext}, {before.ACMECertificateRequests[0].Ciphertext, after.ACMECertificateRequests[0].Ciphertext}} {
		if !bytes.Equal(pair[0], pair[1]) {
			t.Fatal("intent changed existing custody")
		}
	}
	p := requestPayloadFixture(t, key, id, after)
	defer clear(p.PrivateKey)
	public, _ := json.Marshal(status)
	//lint:ignore SA9005 Intentionally prove the opaque lease has no serializable authority, including accidental JSON marshaling.
	serializedAttempt, _ := json.Marshal(attempt)
	if string(serializedAttempt) != "{}" {
		t.Fatal("process-local authority became serializable")
	}
	for _, secret := range [][]byte{p.PrivateKey, p.CSR, []byte(p.Order), []byte("private_key"), []byte("csr"), []byte("example.com")} {
		if bytes.Contains(next, secret) || bytes.Contains(public, secret) {
			t.Fatal("internal issuance scope leaked")
		}
	}
	copied := *attempt // opaque handles share consumption, even if accidentally copied
	calls := 0
	var borrowedPrivate, borrowedCSR []byte
	use := func(signer crypto.Signer, account, order, expires string, names []string, private, csr []byte, refresh bool) error {
		calls++
		if signer == nil || account != registrationURLFixture || order != orderURLFixture || expires == "" || !slices.Equal(names, p.Names) || !bytes.Equal(private, p.PrivateKey) || !bytes.Equal(csr, p.CSR) || refresh {
			t.Fatal("lease changed prepared request/direction")
		}
		if _, err := acmecertrequest.Check(private, csr, names); err != nil {
			t.Fatal("lease material invalid")
		}
		borrowedPrivate, borrowedCSR = private, csr
		return errors.New("private callback sentinel")
	}
	if err := WithStagingIssuance(key, id, next, 12, attempt, use); err != ErrIssuanceUncertain {
		t.Fatal("callback uncertainty reflected raw error or success")
	}
	if !bytes.Equal(borrowedPrivate, make([]byte, len(borrowedPrivate))) || !bytes.Equal(borrowedCSR, make([]byte, len(borrowedCSR))) {
		t.Fatal("owned lease buffers not cleared")
	}
	if err := WithStagingIssuance(key, id, next, 12, &copied, use); err == nil || calls != 1 {
		t.Fatal("copied handle replayed finalize")
	}
	if out, token, s, g, err := BeginStagingIssuance(key, id, next, 12, false); err == nil || out != nil || token != nil || s.State != "" || g != 0 {
		t.Fatal("reopened intent minted another first attempt")
	}
	read, token, s, g, err := BeginStagingIssuance(key, id, next, 12, true)
	if err != nil || read != nil || g != 12 || s != status {
		t.Fatal("same-order refresh rewrote intent or refused")
	}
	if err := WithStagingIssuance(key, id, next, 12, token, func(_ crypto.Signer, account, order, _ string, names []string, private, csr []byte, refresh bool) error {
		if !refresh || account != registrationURLFixture || order != p.Order || !slices.Equal(names, p.Names) || !bytes.Equal(private, p.PrivateKey) || !bytes.Equal(csr, p.CSR) {
			t.Fatal("read-only recovery changed signer/CSR/scope")
		}
		return nil
	}); err != nil {
		t.Fatal("read-only lease refused")
	}
	observed, s, g, err := ObserveStagingIssuance(key, id, next, 12, "processing")
	if err != nil || s.State != "awaiting-certificate" || s.CheckedAt == "" || s.Observation != "processing" || g != 13 {
		t.Fatal("non-issued observation refused")
	}
	if _, _, _, err := ObserveStagingIssuance(key, id, observed, 13, "certificate-received"); err == nil {
		t.Fatal("raw receipt became issuance success")
	}
	if out, _, _, err := BeginStagingValidation(key, id, observed, 13, true); err == nil || out != nil {
		t.Fatal("domain validation invalidated an issuance intent")
	}
	events, _, err := History(key, id, observed)
	if err != nil || events[len(events)-2].Action != "acme-issuance-started" || events[len(events)-1].Action != "acme-issuance-observed" {
		t.Fatal("issuance history lost")
	}
}

func TestIssuanceNonIssuedObservationsNeverGrantFirstAttempt(t *testing.T) {
	key, id, image := issuanceFixture(t)
	image, _, _, _, err := BeginStagingIssuance(key, id, image, 11, false)
	if err != nil {
		t.Fatal(err)
	}
	for observation, state := range map[string]string{"pending": "not-issued", "ready": "not-issued", "processing": "awaiting-certificate", "invalid": "issuance-failed"} {
		next, status, gen, err := ObserveStagingIssuance(key, id, image, 12, observation)
		if err != nil || gen != 13 || status.State != state || status.Observation != observation || status.CheckedAt == "" {
			t.Fatal("non-issued observation lost its honest state")
		}
		if out, token, s, g, err := BeginStagingIssuance(key, id, next, 13, false); err == nil || out != nil || token != nil || s.State != "" || g != 0 {
			t.Fatal("non-issued observation regained finalize authority")
		}
		read, token, s, g, err := BeginStagingIssuance(key, id, next, 13, true)
		if err != nil || read != nil || token == nil || s != status || g != 13 {
			t.Fatal("same-order read refused after non-issued observation")
		}
	}
}

func TestIssuanceAttemptConcurrentCopiesPermitOnlyOneCallback(t *testing.T) {
	key, id, image := issuanceFixture(t)
	image, attempt, _, _, err := BeginStagingIssuance(key, id, image, 11, false)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		copyOf := *attempt
		group.Go(func() {
			_ = WithStagingIssuance(key, id, image, 12, &copyOf, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) error {
				calls.Add(1)
				return nil
			})
		})
	}
	group.Wait()
	if calls.Load() != 1 {
		t.Fatal("concurrent copied leases replayed finalize")
	}
}

func issuanceRawImage(t *testing.T, key, id []byte, m manifest, raw []byte) []byte {
	t.Helper()
	k, _ := issuanceKey(key, id)
	defer clear(k)
	item := m.ACMEIssuances[0]
	item.Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, item), raw)
	m.ACMEIssuances = []sealedRecord{item}
	image, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	return image
}

func TestIssuanceIntentWholeImageTamperScopePurposeAndNoPartialOutput(t *testing.T) {
	key, id, image := issuanceFixture(t)
	image, _, _, _, err := BeginStagingIssuance(key, id, image, 11, false)
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := decode(key, id, image)
	p, err := openIssuance(key, id, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*issuancePayload){
		func(p *issuancePayload) { p.StartedAt = "2020-01-01T00:00:00Z" }, func(p *issuancePayload) { p.StartedGeneration = 1 },
		func(p *issuancePayload) { p.AccountFingerprint = "" }, func(p *issuancePayload) { p.KeyFingerprint = "" }, func(p *issuancePayload) { p.RequestFingerprint = "" },
		func(p *issuancePayload) { p.Order = orderURLFixture + "?secret=sentinel" }, func(p *issuancePayload) { p.Names = []string{"other.example.com"} },
		func(p *issuancePayload) { p.Observation = "valid" }, func(p *issuancePayload) { p.CheckedAt = p.StartedAt },
		func(p *issuancePayload) { p.Observation = "processing" },
	} {
		copyOf := p
		mutate(&copyOf)
		raw, _ := json.Marshal(copyOf)
		bad := issuanceRawImage(t, key, id, m, raw)
		if s, g, err := ReadStagingIssuance(key, id, bad); err == nil || s.State != "" || g != 0 {
			t.Fatal("invalid authenticated issuance returned authority")
		}
		if records, g, err := Open(key, id, bad); err == nil || records != nil || g != 0 {
			t.Fatal("whole-image issuance refusal returned partial data")
		}
	}
	for _, mutation := range []func(*manifest){
		func(m *manifest) { m.ACMEIssuances = append(m.ACMEIssuances, m.ACMEIssuances[0]) },
		func(m *manifest) { m.ACMEIssuances[0].ID = certificateRequestID() },
		func(m *manifest) { m.ACMEIssuances[0].Generation = 1 },
		func(m *manifest) {
			m.ACMEIssuances[0].Ciphertext = bytes.Clone(m.ACMEIssuances[0].Ciphertext)
			m.ACMEIssuances[0].Ciphertext[0] ^= 1
		},
		func(m *manifest) { m.ACMEIssuances[0].Ciphertext = m.ACMECertificateRequests[0].Ciphertext },
	} {
		copyOf := m
		copyOf.ACMEIssuances = slices.Clone(m.ACMEIssuances)
		mutation(&copyOf)
		bad, err := encode(key, copyOf)
		if err != nil {
			t.Fatal(err)
		}
		if s, g, err := ReadStagingIssuance(key, id, bad); err == nil || s.State != "" || g != 0 {
			t.Fatal("tampered context/purpose accepted")
		}
	}
}

func TestIssuancePreflightStaleExpiryClockAndLeaseImageBinding(t *testing.T) {
	key, id, image := issuanceFixture(t)
	for _, tc := range []struct {
		gen     uint64
		refresh bool
		at      time.Time
	}{
		{10, false, time.Now()}, {11, true, time.Now()}, {11, false, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}, {11, false, time.Now().Add(24 * time.Hour)}, {11, false, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		if out, token, s, g, err := beginStagingIssuanceAt(key, id, image, tc.gen, tc.refresh, tc.at); err == nil || out != nil || token != nil || s.State != "" || g != 0 {
			t.Fatal("stale/expired/unstarted/clock request accepted")
		}
	}
	next, attempt, _, _, err := BeginStagingIssuance(key, id, image, 11, false)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	use := func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) error {
		called = true
		return nil
	}
	for _, token := range []*IssuanceAttempt{nil, {}, mintIssuanceAttempt(image, 12, false)} {
		if err := WithStagingIssuance(key, id, next, 12, token, use); err == nil || called {
			t.Fatal("fabricated/other image token reached callback")
		}
	}
	if err := WithStagingIssuance(key, id, next, 11, attempt, use); !errors.Is(err, ErrStaleGeneration) || called {
		t.Fatal("stale lease callback")
	}
	if err := WithStagingIssuance(key, id, next, 12, attempt, nil); err == nil {
		t.Fatal("nil callback accepted")
	}
	if err := WithStagingIssuance(key, id, next, 12, attempt, use); err != nil || !called {
		t.Fatal("unused valid lease refused")
	}
	before, _, _ := Open(key, id, next)
	added, _, err := Append(key, id, next, demo(t, "rootwell-demo-certificate.pem"), "owner", "service")
	if err != nil {
		t.Fatal(err)
	}
	state, gen, err := ReadStagingIssuance(key, id, added)
	if err != nil || gen != 13 || state.State != "issuance-pending" {
		t.Fatal("certificate mutation lost intent")
	}
	if len(before) != 0 {
		t.Fatal("fixture unexpectedly had records")
	}
}

func TestIssuanceReservesCompletionAndReadOnlySurvivesLastSlot(t *testing.T) {
	key, id, image := issuanceFixture(t)
	m, _, _ := decode(key, id, image)
	m.Generation = maxGeneration - 2
	// No history means a pre-history legacy image: this tests nonce budgeting
	// independently of history depth, not a fabricated invalid event sequence.
	m.History = nil
	image, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	next, _, _, gen, err := BeginStagingIssuance(key, id, image, maxGeneration-2, false)
	if err != nil || gen != maxGeneration-1 {
		t.Fatal("last safe intent slot refused")
	}
	if out, _, _, err := ObserveStagingIssuance(key, id, next, gen, "processing"); !errors.Is(err, ErrLimit) || out != nil {
		t.Fatal("observation consumed completion generation")
	}
	if out, _, err := Append(key, id, next, demo(t, "rootwell-demo-certificate.pem"), "", ""); !errors.Is(err, ErrLimit) || out != nil {
		t.Fatal("generic write consumed completion generation")
	}
	if out, token, _, _, err := BeginStagingIssuance(key, id, next, gen, true); err != nil || out != nil || token == nil {
		t.Fatal("read-only recovery needs a new generation")
	}
	m, _, _ = decode(key, id, next)
	m.ACMEIssuances = nil
	m.Generation = maxGeneration - 1
	m.History = nil
	image, err = encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	if out, token, _, _, err := BeginStagingIssuance(key, id, image, maxGeneration-1, false); !errors.Is(err, ErrLimit) || out != nil || token != nil {
		t.Fatal("irreversible intent did not reserve completion")
	}
}

func TestIssuanceHistoryAndRecordCompletionReservations(t *testing.T) {
	key, id, image := issuanceFixture(t)
	image, records, err := Append(key, id, image, demo(t, "rootwell-demo-certificate.pem"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	for len(m.History) < maxHistory-2 {
		m.Generation++
		if err := addEvent(key, &m, "owner-changed", []string{records[0].Fingerprint}); err != nil {
			t.Fatal(err)
		}
	}
	image, err = encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	next, _, _, gen, err := BeginStagingIssuance(key, id, image, m.Generation, false)
	if err != nil {
		t.Fatal("last safe history intent refused")
	}
	if out, _, _, err := ObserveStagingIssuance(key, id, next, gen, "processing"); !errors.Is(err, ErrLimit) || out != nil {
		t.Fatal("observation consumed final history slot")
	}
	if out, _, _, err := UpdateOwner(key, id, next, records[0].Fingerprint, "different", gen); !errors.Is(err, ErrLimit) || out != nil {
		t.Fatal("ordinary note consumed completion history")
	}
	if out, token, _, _, err := BeginStagingIssuance(key, id, next, gen, true); err != nil || out != nil || token == nil {
		t.Fatal("history-full read-only reconciliation refused")
	}

	key, id, image = issuanceFixture(t)
	m, _, _ = decode(key, id, image)
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer keymatch.ClearParsedKey(signer)
	for i := 0; i < maxRecords; i++ {
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), DNSNames: []string{"slot.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(payload{DER: der})
		h := sha256.Sum256(der)
		item := sealedRecord{ID: h[:], Generation: 2}
		item.Ciphertext, err = inventoryseal.Seal(key, attachmentContext(id, item), raw)
		if err != nil {
			t.Fatal(err)
		}
		m.Records = append(m.Records, item)
	}
	full, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	if out, token, _, _, err := BeginStagingIssuance(key, id, full, 11, false); !errors.Is(err, ErrLimit) || out != nil || token != nil {
		t.Fatal("no certificate slot reserved before intent")
	}
	m.Records = m.Records[:maxRecords-1]
	image, err = encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	next, _, _, _, err = BeginStagingIssuance(key, id, image, 11, false)
	if err != nil {
		t.Fatal("last safe certificate slot refused")
	}
	if out, _, err := Append(key, id, next, demo(t, "rootwell-demo-certificate.pem"), "", ""); !errors.Is(err, ErrLimit) || out != nil {
		t.Fatal("ordinary import consumed pending certificate slot")
	}
	// The reserve remains, but read/status still work and existing data survives.
	if kept, _, err := Open(key, id, next); err != nil || len(kept) != maxRecords-1 {
		t.Fatal("record reservation changed existing certificates")
	}
}

func TestIssuanceByteBudgetBoundary(t *testing.T) {
	key, id, image := issuanceFixture(t)
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise exact budget metrics without allocating a 96 MiB fixture. The
	// constructor uses these bytes from len(the fully authenticated image).
	if !issuanceCapacity(m, len(image)) || !issuanceCapacity(m, maxImage-issuanceByteReserve) {
		t.Fatal("valid capacity decision refused")
	}
	if issuanceCapacity(m, 0) || issuanceCapacity(m, maxImage-issuanceByteReserve+1) || issuanceCapacity(m, maxImage) {
		t.Fatal("insufficient byte headroom granted irreversible capacity")
	}
}

func FuzzStagingIssuancePayload(f *testing.F) {
	f.Add([]byte(`{"started_at":"2026-10-12T00:00:00Z","observation":"valid"}`))
	f.Add([]byte(`{"started_at":null}`))
	var once sync.Once
	var key, id []byte
	var baseline manifest
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 8192 {
			return
		}
		// Each worker builds its synthetic encrypted baseline once. No borrowed
		// private key is cached; issuanceRawImage replaces only a local slice.
		once.Do(func() {
			var image []byte
			key, id, image = issuanceFixture(t)
			next, _, _, _, err := BeginStagingIssuance(key, id, image, 11, false)
			if err != nil {
				t.Fatal(err)
			}
			baseline, _, err = decode(key, id, next)
			if err != nil {
				t.Fatal(err)
			}
		})
		bad := issuanceRawImage(t, key, id, baseline, input)
		s, g, err := ReadStagingIssuance(key, id, bad)
		if err != nil && (!reflect.DeepEqual(s, IssuanceStatus{}) || g != 0) {
			t.Fatal("partial issuer metadata escaped")
		}
		if err == nil && s.State != "issuance-pending" && s.State != "not-issued" && s.State != "awaiting-certificate" && s.State != "issuance-failed" {
			t.Fatal("fuzzed payload fabricated certificate issuance")
		}
	})
}
