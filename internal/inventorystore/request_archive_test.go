package inventorystore

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func appendExpiredArchiveFixture(t testing.TB, key, id, image []byte, index int, at time.Time) []byte {
	t.Helper()
	_, g, err := Open(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"*.example.com", "example.com"}
	image, _, g, err = beginStagingOrderAt(key, id, image, g, names, at)
	if err != nil {
		t.Fatal("fixture intent", err)
	}
	info := orderInstructionsFixture()
	info.URL = acmeorder.Origin + fmt.Sprintf("/acme/order/1234/%d", 10000+index)
	info.Expires = at.Add(time.Second).Format(time.RFC3339)
	image, _, g, err = UpdateStagingOrder(key, id, image, g, info.URL, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, g, err = UpdateStagingOrder(key, id, image, g, "", &info, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = closeStagingRequestAt(key, id, image, g, at.Add(time.Second))
	if err != nil {
		t.Fatal("fixture closure", err)
	}
	return image
}

func requestArchiveFixture(t testing.TB, count int) ([]byte, []byte, []byte, time.Time) {
	t.Helper()
	key, id, image := registeredOrderFixture(t)
	at := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	for i := 0; i < count; i++ {
		image = appendExpiredArchiveFixture(t, key, id, image, i, at)
		at = at.Add(2 * time.Second)
	}
	return key, id, image, at
}

func TestRequestArchiveFullActiveLosslessAndNextClosure(t *testing.T) {
	key, id, image, at := requestArchiveFixture(t, maxClosedRequests)
	defer clear(key)
	before, _, _ := decode(key, id, image)
	beforeEvents, _, _ := History(key, id, image)
	next, s, err := archiveClosedRequestsAt(key, id, image, before.Generation, at)
	if err != nil || s.Active != 0 || s.Archived != 32 || s.PagesFree != 3 || s.CanArchive || s.Generation != before.Generation+1 {
		t.Fatal("full active repack refused", err, s)
	}
	after, _, err := decode(key, id, next)
	if err != nil || !reflect.DeepEqual(before.ClosedRequests, after.ClosedRequestArchives[0]) || !reflect.DeepEqual(before.ACMEAccounts, after.ACMEAccounts) || after.ClosedRequestArchiveCount != 32 {
		t.Fatal("repack changed original ciphertext", err)
	}
	events, _, err := History(key, id, next)
	if err != nil || len(events) != len(beforeEvents)+1 || !reflect.DeepEqual(beforeEvents, events[:len(beforeEvents)]) || events[len(events)-1].Action != "acme-request-history-archived" {
		t.Fatal("repack lost history", err)
	}
	next = appendExpiredArchiveFixture(t, key, id, next, 32, at.Add(time.Minute))
	status, _, err := ReadNewStagingRequest(key, id, next)
	if err != nil || status.ClosedCount != 33 {
		t.Fatal("freed capacity or retained count lost", err)
	}
	if status, _, err := ReadNewStagingRequest(key, id, image); err != nil || status.ClosedCount != 32 {
		t.Fatal("old snapshot mutated", err)
	}
	for _, secret := range []string{orderURLFixture, "PRIVATE KEY", "acme-request-history-archived"} {
		if bytes.Contains(next, []byte(secret)) {
			t.Fatal("public archive envelope leaked content")
		}
	}
}

func TestRequestArchiveRefusesStaleClockMalformedOrDroppedPages(t *testing.T) {
	key, id, image, at := requestArchiveFixture(t, minClosedRequestArchive)
	defer clear(key)
	m, _, _ := decode(key, id, image)
	for _, g := range []uint64{0, m.Generation - 1, m.Generation + 1} {
		if out, s, err := archiveClosedRequestsAt(key, id, image, g, at); !errors.Is(err, ErrStaleGeneration) || out != nil || s != (RequestArchiveStatus{}) {
			t.Fatal("stale archive admitted")
		}
	}
	if out, _, err := archiveClosedRequestsAt(key, id, image, m.Generation, at.Add(-24*time.Hour)); err == nil || out != nil {
		t.Fatal("backward clock repack admitted")
	}
	next, _, err := archiveClosedRequestsAt(key, id, image, m.Generation, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*manifest){
		func(m *manifest) { m.ClosedRequestArchives = nil },
		func(m *manifest) { m.ClosedRequestArchiveCount = 0 },
		func(m *manifest) { m.ClosedRequestArchives[0] = nil },
		func(m *manifest) {
			m.ClosedRequestArchives = append(m.ClosedRequestArchives, m.ClosedRequestArchives[0])
		},
		func(m *manifest) { p := m.ClosedRequestArchives[0]; p[0], p[1] = p[1], p[0] },
		func(m *manifest) { m.ClosedRequestArchives[0][0].Ciphertext[0] ^= 1 },
		func(m *manifest) { m.ClosedRequestArchiveCount = -1 },
		func(m *manifest) { m.ClosedRequests = append(m.ClosedRequests, m.ClosedRequestArchives[0][0]) },
		func(m *manifest) { m.ClosedRequestArchives = make([][]sealedRecord, maxClosedRequestArchives+1) },
	} {
		bad, _, _ := decode(key, id, next)
		edit(&bad)
		corrupt, err := encode(key, bad)
		if err != nil {
			t.Fatal(err)
		}
		if s, err := ReadRequestArchive(key, id, corrupt); err == nil || s != (RequestArchiveStatus{}) {
			t.Fatal("corrupt archive exposed partial status")
		}
	}
	if out, _, err := ArchiveClosedRequests(key, id, next, m.Generation+1); err == nil || out != nil {
		t.Fatal("empty active page archived")
	}
}

func TestRequestArchiveAllPagesFiniteNoPruning(t *testing.T) {
	key, id, image, at := requestArchiveFixture(t, 0)
	defer clear(key)
	index := 0
	for page := 0; page < maxClosedRequestArchives; page++ {
		for i := 0; i < maxClosedRequests; i++ {
			image = appendExpiredArchiveFixture(t, key, id, image, index, at)
			index++
			at = at.Add(2 * time.Second)
		}
		_, g, _ := Open(key, id, image)
		var err error
		image, _, err = archiveClosedRequestsAt(key, id, image, g, at)
		if err != nil {
			t.Fatal("retained page refused", page, err)
		}
	}
	for i := 0; i < maxClosedRequests; i++ {
		image = appendExpiredArchiveFixture(t, key, id, image, index, at)
		index++
		at = at.Add(2 * time.Second)
	}
	m, _, _ := decode(key, id, image)
	if closedRequestCount(m) != 160 {
		t.Fatal("retained scopes lost")
	}
	if out, s, err := archiveClosedRequestsAt(key, id, image, m.Generation, at); !errors.Is(err, ErrLimit) || out != nil || s != (RequestArchiveStatus{}) {
		t.Fatal("page limit bypassed")
	}
	before := bytes.Clone(image)
	if out, _, _, err := beginStagingOrderAt(key, id, image, m.Generation, []string{"example.com"}, at); err == nil || out != nil {
		t.Fatal("new scope ignored full closure capacity")
	}
	if !bytes.Equal(image, before) {
		t.Fatal("full archive silently pruned")
	}
}

func TestRequestArchivePreservesUnknownActiveWorkAndReservations(t *testing.T) {
	key, id, image, at := requestArchiveFixture(t, minClosedRequestArchive)
	defer clear(key)
	_, g, _ := Open(key, id, image)
	image, _, g, err := beginStagingOrderAt(key, id, image, g, []string{"example.com"}, at)
	if err != nil {
		t.Fatal(err)
	}
	before, _, _ := decode(key, id, image)
	if reason, err := closeEligibility(key, id, before, at.Format(time.RFC3339)); err != nil || reason != "unknown-order" {
		t.Fatal("fixture is not uncertain")
	}
	next, s, err := archiveClosedRequestsAt(key, id, image, g, at.Add(time.Second))
	if err != nil || s.Archived != 16 {
		t.Fatal("safe closed history movement refused", err)
	}
	after, _, _ := decode(key, id, next)
	if !reflect.DeepEqual(before.ACMEOrders, after.ACMEOrders) || !reflect.DeepEqual(before.ACMEAccounts, after.ACMEAccounts) || !reflect.DeepEqual(before.DNSPlans, after.DNSPlans) || !reflect.DeepEqual(before.CloudflareConfigs, after.CloudflareConfigs) || !reflect.DeepEqual(before.StagingProviderWait, after.StagingProviderWait) {
		t.Fatal("repack changed active authority or credentials")
	}
	if reason, err := closeEligibility(key, id, after, at.Add(time.Second).Format(time.RFC3339)); err != nil || reason != "unknown-order" {
		t.Fatal("repack abandoned uncertainty")
	}
	full := fillArchiveHistory(t, key, id, image, maxHistory-2)
	_, g, _ = Open(key, id, full)
	if out, _, err := archiveClosedRequestsAt(key, id, full, g, at.Add(time.Second)); err == nil || out != nil {
		t.Fatal("request repack stole pending order's two reserved outcomes")
	}
}

func TestRequestArchiveRetainsPairSourceAndUpdatesArchivedTombstone(t *testing.T) {
	key, id, _, done, _, fp, _ := syntheticCompletion(t)
	defer clear(key)
	image, _, _, err := CloseStagingRequest(key, id, done, 13)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	for i := 1; i < minClosedRequestArchive; i++ {
		image = appendExpiredArchiveFixture(t, key, id, image, i, at)
		at = at.Add(2 * time.Second)
	}
	_, g, _ := Open(key, id, image)
	image, _, err = archiveClosedRequestsAt(key, id, image, g, at)
	if err != nil {
		t.Fatal(err)
	}
	m, records, err := decode(key, id, image)
	if err != nil || len(records) != 1 || records[0].StagingOrigin == nil {
		t.Fatal("archived completion lost certificate provenance", err)
	}
	if source, _, err := ReadStagingRenewalSource(key, id, image, m.Generation, fp); err != nil || source.Fingerprint != fp {
		t.Fatal("retained source hidden from renewal", err)
	}
	if err := WithCertificate(key, id, image, fp, m.Generation, func(_ publicinventory.Record, k []byte) error {
		if len(k) == 0 {
			t.Fatal("private material lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := m.ClosedRequestArchives[0][0]
	next, ng, err := DeleteRecord(key, id, image, fp, m.Generation)
	if err != nil {
		t.Fatal("archived pair deletion refused", err)
	}
	after, rows, err := decode(key, id, next)
	if err != nil || len(rows) != 0 || len(after.Materials) != 0 || after.Generation != ng || bytes.Equal(before.Ciphertext, after.ClosedRequestArchives[0][0].Ciphertext) {
		t.Fatal("wrong archived item updated", err)
	}
	_, _, issued, err := openClosedRequest(key, id, after, after.ClosedRequestArchives[0][0])
	if err != nil || issued.Completion == nil || issued.Completion.DeletedAt == "" {
		t.Fatal("archived deletion tombstone missing", err)
	}
	if _, _, err := ReadStagingRenewalSource(key, id, next, ng, fp); err == nil {
		t.Fatal("deleted archived pair regained renewal authority")
	}
	for i := 1; i < len(m.ClosedRequestArchives[0]); i++ {
		if !reflect.DeepEqual(m.ClosedRequestArchives[0][i], after.ClosedRequestArchives[0][i]) {
			t.Fatal("unrelated archive ciphertext changed")
		}
	}
}
