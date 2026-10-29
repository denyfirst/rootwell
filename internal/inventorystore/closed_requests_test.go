package inventorystore

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func TestClosedCompletedRequestPreservesPairOriginNotesDeleteAndNewOrder(t *testing.T) {
	key, id, _, done, _, fp, _ := syntheticCompletion(t)
	defer clear(key)
	before, records, err := decode(key, id, done)
	if err != nil {
		t.Fatal(err)
	}
	origin := *records[0].StagingOrigin
	var hash [32]byte
	if err := WithCertificate(key, id, done, fp, 13, func(_ publicinventory.Record, private []byte) error { hash = sha256.Sum256(private); return nil }); err != nil {
		t.Fatal(err)
	}
	closed, s, g, err := CloseStagingRequest(key, id, done, 13)
	if err != nil || g != 14 || s.Available || s.Reason != "not-started" || s.ClosedCount != 1 {
		t.Fatal("valid completed closure refused")
	}
	m, records, err := decode(key, id, closed)
	if err != nil || len(records) != 1 || records[0].StagingOrigin == nil || *records[0].StagingOrigin != origin || len(m.ACMEOrders) != 0 || len(m.ACMECertificateRequests) != 0 || len(m.ACMEIssuances) != 0 || !bytes.Equal(before.Materials[0].Ciphertext, m.Materials[0].Ciphertext) || !bytes.Equal(before.ACMEAccounts[0].Ciphertext, m.ACMEAccounts[0].Ciphertext) {
		t.Fatal("closure lost prior exact custody/provenance")
	}
	if err := WithCertificate(key, id, closed, fp, 14, func(_ publicinventory.Record, private []byte) error {
		if sha256.Sum256(private) != hash {
			t.Fatal("archive changed private key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if next, _, _, err := CloseStagingRequest(key, id, closed, 14); err == nil || next != nil {
		t.Fatal("closed request closed again")
	}
	newImage, _, gen, err := BeginStagingOrder(key, id, closed, 14, []string{"new.example.com"})
	if err != nil || gen != 15 {
		t.Fatal("new explicit order refused")
	}
	oldOrder, err := openOrder(key, id, before)
	if err != nil {
		t.Fatal(err)
	}
	if next, _, _, err := UpdateStagingOrder(key, id, newImage, 15, oldOrder.URL, nil, false); err == nil || next != nil {
		t.Fatal("old CA order URI resurrected")
	}
	newURL := acmeorder.Origin + "/acme/order/1234/9999"
	newImage, _, gen, err = UpdateStagingOrder(key, id, newImage, 15, newURL, nil, false)
	if err != nil || gen != 16 {
		t.Fatal("distinct new order refused")
	}
	newImage, _, gen, err = UpdateOwner(key, id, newImage, fp, "retained note", 16)
	if err != nil || gen != 17 {
		t.Fatal("archived certificate metadata edit refused")
	}
	newImage, gen, err = DeleteRecord(key, id, newImage, fp, 17)
	if err != nil || gen != 18 {
		t.Fatal("archived completion deletion refused")
	}
	m, records, err = decode(key, id, newImage)
	if err != nil || len(records) != 0 || len(m.Materials) != 0 {
		t.Fatal("delete did not remove archived pair")
	}
	p, _, issuance, err := openClosedRequest(key, id, m, m.ClosedRequests[0])
	if err != nil || len(p.Requests) != 0 || issuance.Completion == nil || issuance.Completion.DeletedAt == "" {
		t.Fatal("closed public tombstone not retained")
	}
	if _, records, err := decode(key, id, closed); err != nil || len(records) != 1 {
		t.Fatal("old backup mutated")
	}
}

func TestClosedExpiredRequestPreservesKeyButCannotReopenLease(t *testing.T) {
	key, id, image := issuanceFixture(t)
	defer clear(key)
	image, lease, _, _, err := BeginStagingIssuance(key, id, image, 11, false)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	p, err := openIssuance(key, id, m)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := time.Parse("2006-01-02T15:04:05Z", p.Expires)
	if next, _, _, err := closeStagingRequestAt(key, id, image, 12, deadline.Add(-time.Second)); err == nil || next != nil {
		t.Fatal("active uncertainty replaced")
	}
	closed, _, gen, err := closeStagingRequestAt(key, id, image, 12, deadline)
	if err != nil || gen != 13 {
		t.Fatal("known expired uncertainty cannot close")
	}
	if err := WithStagingIssuance(key, id, closed, 13, lease, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) error {
		t.Fatal("old lease regained authority")
		return nil
	}); err == nil {
		t.Fatal("archived intent became active")
	}
	cm, _, err := decode(key, id, closed)
	if err != nil {
		t.Fatal(err)
	}
	archive, scope, _, err := openClosedRequest(key, id, cm, cm.ClosedRequests[0])
	if err != nil || archive.Reason != "expired" || !bytes.Equal(scope.ACMECertificateRequests[0].Ciphertext, m.ACMECertificateRequests[0].Ciphertext) {
		t.Fatal("expired prepared key was discarded")
	}
	if _, _, _, _, err := BeginStagingIssuance(key, id, closed, 13, true); err == nil {
		t.Fatal("closed scope exported active read lease")
	}
	// Historical pending validation is independent of new active completion
	// reservations, so reaching later image limits must not lose retained keys.
	cm.Generation = maxGeneration
	for len(cm.History) < maxHistory {
		cm.History = append(cm.History, sealedRecord{})
	}
	if _, _, _, err := openClosedRequest(key, id, cm, cm.ClosedRequests[0]); err != nil {
		t.Fatal("historical scope acquired active capacity constraints")
	}
}

func TestClosedDeletedRequestAndOuterPurposeContextRefusals(t *testing.T) {
	key, id, _, completed, _, fp, _ := syntheticCompletion(t)
	defer clear(key)
	deleted, gen, err := DeleteRecord(key, id, completed, fp, 13)
	if err != nil || gen != 14 {
		t.Fatal("pre-closure deletion refused")
	}
	closed, s, gen, err := CloseStagingRequest(key, id, deleted, 14)
	if err != nil || gen != 15 || s.ClosedCount != 1 || s.Reason != "not-started" {
		t.Fatal("legitimate deleted completion cannot close")
	}
	m, records, err := decode(key, id, closed)
	if err != nil || len(records) != 0 || len(m.Materials) != 0 {
		t.Fatal("closure resurrected deleted material")
	}
	p, _, issuance, err := openClosedRequest(key, id, m, m.ClosedRequests[0])
	if err != nil || len(p.Requests) != 0 || issuance.Completion == nil || issuance.Completion.DeletedAt == "" {
		t.Fatal("deleted closed tombstone lost")
	}
	for _, mutate := range []func(*sealedRecord){
		func(item *sealedRecord) { item.ID = append([]byte{}, item.ID...); item.ID[0] ^= 1 },
		func(item *sealedRecord) { item.Generation-- },
		func(item *sealedRecord) { item.Ciphertext = nil },
		func(item *sealedRecord) {
			item.Ciphertext = append([]byte{}, item.Ciphertext...)
			item.Ciphertext[len(item.Ciphertext)-1] ^= 1
		},
		func(item *sealedRecord) {
			item.Ciphertext = append([]byte{}, item.Ciphertext[:len(item.Ciphertext)-1]...)
		},
		func(item *sealedRecord) { item.Ciphertext = make([]byte, maxClosedRequestBytes+1) },
		func(item *sealedRecord) {
			plain, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(plain)
			wrongPurpose, err := issuanceKey(key, id)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(wrongPurpose)
			item.Ciphertext, err = inventoryseal.Seal(wrongPurpose, attachmentContext(id, *item), plain)
			if err != nil {
				t.Fatal(err)
			}
		},
	} {
		bad := m
		bad.ClosedRequests = append([]sealedRecord{}, m.ClosedRequests...)
		mutate(&bad.ClosedRequests[0])
		image, err := encode(key, bad)
		if err != nil {
			t.Fatal(err)
		}
		if records, gen, err := Open(key, id, image); err == nil || records != nil || gen != 0 {
			t.Fatal("closed purpose/context corruption produced partial output")
		}
	}
}

func TestClosedRequestStaleUnknownClockTamperAndLimitsRefuse(t *testing.T) {
	key, id, _, done, _, _, _ := syntheticCompletion(t)
	defer clear(key)
	if next, _, g, err := CloseStagingRequest(key, id, done, 12); err == nil || next != nil || g != 0 {
		t.Fatal("stale closure accepted")
	}
	closed, _, _, err := CloseStagingRequest(key, id, done, 13)
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := decode(key, id, closed)
	p, _, _, err := openClosedRequest(key, id, m, m.ClosedRequests[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*closedRequest){func(p *closedRequest) { p.Reason = "expired" }, func(p *closedRequest) { p.ClosedAt = "2020-01-01T00:00:00Z" }, func(p *closedRequest) { p.ClosedGeneration = 13 }, func(p *closedRequest) { p.Requests = nil }, func(p *closedRequest) { p.Orders = nil }, func(p *closedRequest) { p.Issuances = nil }} {
		bad := m
		bad.ClosedRequests = append([]sealedRecord{}, m.ClosedRequests...)
		changed := p
		mutate(&changed)
		if err := sealClosedRequest(key, id, &bad, 0, changed, acmeorder.Origin+"/acme/order/1234/5678"); err != nil {
			t.Fatal(err)
		}
		image, err := encode(key, bad)
		if err != nil {
			t.Fatal(err)
		}
		if records, g, err := Open(key, id, image); err == nil || records != nil || g != 0 {
			t.Fatal("tampered closed scope returned partial custody")
		}
	}
	bad := m
	bad.ClosedRequests = append(append([]sealedRecord{}, m.ClosedRequests...), m.ClosedRequests[0])
	image, _ := encode(key, bad)
	if _, _, err := Open(key, id, image); err == nil {
		t.Fatal("duplicate archived order accepted")
	}
	prepared, _, _, err := BeginStagingOrder(key, id, closed, 14, []string{"new.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if next, _, _, err := CloseStagingRequest(key, id, prepared, 15); err == nil || next != nil {
		t.Fatal("unknown order erased uncertainty")
	}
	if s, err := newRequestStatus(key, id, m, "2020-01-01T00:00:00Z"); err != nil || s.Available || s.Reason != "clock-unavailable" {
		t.Fatal("backward clock granted new scope")
	}
	complete, _, _ := decode(key, id, done)
	complete.Generation = maxGeneration
	if s, err := newRequestStatus(key, id, complete, time.Now().UTC().Format("2006-01-02T15:04:05Z")); err != nil || s.Available || s.Reason != "capacity" {
		t.Fatal("generation ceiling permits closure")
	}
	tooMany := m
	tooMany.ClosedRequests = make([]sealedRecord, maxClosedRequests+1)
	image, _ = encode(key, tooMany)
	if records, g, err := Open(key, id, image); err == nil || records != nil || g != 0 {
		t.Fatal("closed request count unbounded")
	}
}

func FuzzClosedStagingRequest(f *testing.F) {
	f.Add([]byte(`null`))
	f.Add([]byte(`{"reason":"expired"}`))
	var once sync.Once
	var key, id []byte
	var m manifest
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) == 0 || len(raw) > maxClosedRequestBytes-64 {
			return
		}
		once.Do(func() {
			var done, closed []byte
			key, id, _, done, _, _, _ = syntheticCompletion(t)
			closed, _, _, _ = CloseStagingRequest(key, id, done, 13)
			m, _, _ = decode(key, id, closed)
		})
		bad := m
		bad.ClosedRequests = append([]sealedRecord{}, m.ClosedRequests...)
		k, err := closedRequestKey(key, id)
		if err != nil {
			t.Fatal(err)
		}
		bad.ClosedRequests[0].Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, bad.ClosedRequests[0]), raw)
		clear(k)
		if err != nil {
			t.Fatal(err)
		}
		image, err := encode(key, bad)
		if err != nil {
			t.Fatal(err)
		}
		records, g, err := Open(key, id, image)
		if err != nil && (records != nil || g != 0) {
			t.Fatal("fuzzed archive exposed partial records")
		}
	})
}

func TestClosedRequestsRepeatedCyclesExactCapacityAndNoSilentPruning(t *testing.T) {
	key, id, image := registeredOrderFixture(t)
	defer clear(key)
	at := time.Now().UTC().Truncate(time.Second).Add(2 * time.Hour)
	gen := uint64(4)
	names := []string{"*.example.com", "example.com"}
	for i := 0; i < maxClosedRequests; i++ {
		var err error
		image, _, gen, err = beginStagingOrderAt(key, id, image, gen, names, at)
		if err != nil {
			t.Fatal("next independent intent refused")
		}
		info := orderInstructionsFixture()
		info.URL = acmeorder.Origin + fmt.Sprintf("/acme/order/1234/%d", 1000+i)
		info.Expires = at.Add(time.Second).Format("2006-01-02T15:04:05Z")
		image, _, gen, err = UpdateStagingOrder(key, id, image, gen, info.URL, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		image, _, gen, err = UpdateStagingOrder(key, id, image, gen, "", &info, false)
		if err != nil {
			t.Fatal(err)
		}
		var status NewRequestStatus
		image, status, gen, err = closeStagingRequestAt(key, id, image, gen, at.Add(time.Second))
		if err != nil || status.ClosedCount != i+1 {
			t.Fatal("eligible expiry cycle lost retained history")
		}
		at = at.Add(2 * time.Second)
	}
	if next, _, _, err := beginStagingOrderAt(key, id, image, gen, names, at); err == nil || next != nil {
		t.Fatal("new order consumed capacity before its future closure could fit")
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newRequestStatus(key, id, m, at.Format(time.RFC3339))
	if err != nil || s.Available || s.Reason != "capacity" || s.ClosedCount != maxClosedRequests {
		t.Fatal("closed scope ceiling bypassed")
	}
	if next, _, g, err := closeStagingRequestAt(key, id, image, gen, at.Add(time.Second)); err == nil || next != nil || g != 0 {
		t.Fatal("full history silently pruned or closed")
	}
}
