package inventorystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"reflect"
	"testing"
	"time"
)

func fillArchiveHistory(t *testing.T, key, id, image []byte, count int) []byte {
	t.Helper()
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal("archive fixture", err)
	}
	events, err := openHistory(key, id, m)
	if err != nil || len(events) == 0 {
		t.Fatal("archive fixture history", err)
	}
	fp := events[len(events)-1].Fingerprints[0]
	for len(m.History) < count {
		m.Generation++
		if err := addEvent(key, &m, "owner-changed", []string{fp}); err != nil {
			t.Fatal(err)
		}
	}
	next, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func TestHistoryArchiveLosslessAtFullLimitAndContinues(t *testing.T) {
	key, id := testIdentity(t)
	image, _ := Create(key, id)
	image, _, _ = Append(key, id, image, demo(t, "rootwell-demo-certificate.pem"), "private-owner-sentinel", "private-location-sentinel")
	image = fillArchiveHistory(t, key, id, image, maxHistory)
	beforeRecords, g, _ := Open(key, id, image)
	beforeEvents, _, _ := History(key, id, image)
	beforeM, _, _ := decode(key, id, image)
	next, s, err := ArchiveHistory(key, id, image, g)
	if err != nil || s.Generation != g+1 || s.Active != 1 || s.Archived != maxHistory || s.PagesFree != 3 || s.CanArchive {
		t.Fatal("legitimate full history archive refused", err, s)
	}
	afterRecords, _, err := Open(key, id, next)
	afterEvents, _, err2 := History(key, id, next)
	if err != nil || err2 != nil || !reflect.DeepEqual(beforeRecords, afterRecords) || len(afterEvents) != maxHistory+1 || !reflect.DeepEqual(beforeEvents, afterEvents[:maxHistory]) || afterEvents[maxHistory].Action != "history-archived" {
		t.Fatal("archive lost records/history", err, err2)
	}
	afterM, _, _ := decode(key, id, next)
	if !reflect.DeepEqual(beforeM.History, afterM.HistoryArchives[0]) {
		t.Fatal("old ciphertext or nonce context changed")
	}
	for _, secret := range []string{"private-owner-sentinel", "private-location-sentinel", "owner-changed", "PRIVATE KEY", beforeEvents[0].Fingerprints[0]} {
		if bytes.Contains(next, []byte(secret)) {
			t.Fatal("archive leaked private metadata")
		}
	}
	next, _, _, err = UpdateOwner(key, id, next, beforeRecords[0].Fingerprint, "next-owner", g+1)
	if err != nil {
		t.Fatal("archive failed to release active capacity", err)
	}
	events, _, err := History(key, id, next)
	if err != nil || len(events) != maxHistory+2 {
		t.Fatal("append lost archived events")
	}
	for _, tc := range []string{"replay-page", "drop-page", "drop-whole-page", "swap", "ciphertext", "empty-active", "wrong-id", "wrong-key", "oversize-page"} {
		t.Run(tc, func(t *testing.T) {
			m, _, _ := decode(key, id, next)
			k, install := key, id
			switch tc {
			case "replay-page":
				m.HistoryArchives = append(m.HistoryArchives, m.HistoryArchives[0])
			case "drop-page":
				m.HistoryArchives[0] = m.HistoryArchives[0][1:]
			case "drop-whole-page":
				m.HistoryArchives = m.HistoryArchives[1:]
			case "swap":
				p := m.HistoryArchives[0]
				p[0], p[1] = p[1], p[0]
			case "ciphertext":
				m.HistoryArchives[0][0].Ciphertext[0] ^= 1
			case "empty-active":
				m.History = nil
			case "wrong-id":
				install = bytes.Repeat([]byte{2}, 16)
			case "wrong-key":
				k = bytes.Repeat([]byte{3}, 32)
			case "oversize-page":
				m.HistoryArchives[0] = append(m.HistoryArchives[0], m.History[0])
			}
			bad, _ := encode(key, m)
			records, _, e := Open(k, install, bad)
			events, _, he := History(k, install, bad)
			if e == nil || he == nil || records != nil || events != nil {
				t.Fatal("corrupt archive exposed partial output")
			}
		})
	}
}

func TestHistoryArchiveAdmissionNeverResetsOrDiscards(t *testing.T) {
	key, id := testIdentity(t)
	image, _ := Create(key, id)
	image, _, _ = Append(key, id, image, demo(t, "rootwell-demo-certificate.pem"), "", "")
	image = fillArchiveHistory(t, key, id, image, minArchiveEvents)
	_, g, _ := Open(key, id, image)
	if out, _, err := ArchiveHistory(key, id, image, g-1); !errors.Is(err, ErrStaleGeneration) || out != nil {
		t.Fatal("stale archive admitted")
	}
	for page := 0; page < maxHistoryArchives; page++ {
		image = fillArchiveHistory(t, key, id, image, minArchiveEvents)
		_, g, _ = Open(key, id, image)
		next, _, err := ArchiveHistory(key, id, image, g)
		if err != nil {
			t.Fatal("bounded archive refused", page, err)
		}
		image = next
	}
	image = fillArchiveHistory(t, key, id, image, minArchiveEvents)
	_, g, _ = Open(key, id, image)
	before := bytes.Clone(image)
	out, s, err := ArchiveHistory(key, id, image, g)
	if !errors.Is(err, ErrLimit) || out != nil || s != (HistoryArchiveStatus{}) || !bytes.Equal(before, image) {
		t.Fatal("archive limit silently drops history")
	}
	// Future authenticated history is not made current by repacking it.
	m, records, _ := decode(key, id, image)
	m.HistoryArchives = nil
	m.HistoryArchiveStart = 0
	last := &m.History[len(m.History)-1]
	plain, _ := json.Marshal(Event{Generation: last.Generation, At: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), Action: "owner-changed", Fingerprints: []string{records[0].Fingerprint}})
	last.Ciphertext, err = inventoryseal.Seal(key, eventContext(id, last.Generation), plain)
	if err != nil {
		t.Fatal(err)
	}
	future, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	if out, _, err := ArchiveHistory(key, id, future, m.Generation); err == nil || out != nil {
		t.Fatal("future history was made current")
	}
}

func TestHistoryArchivePreservesPendingDNSAndTiming(t *testing.T) {
	key, id, image, fp, at := timingFixture(t)
	image, _, _, err := beginTimingAt(key, id, image, 13, fp, at)
	if err != nil {
		t.Fatal(err)
	}
	image = fillArchiveHistory(t, key, id, image, minArchiveEvents)
	m, _, _ := decode(key, id, image)
	old := m.RenewalTimings
	wait := m.StagingProviderWait
	next, _, err := ArchiveHistory(key, id, image, m.Generation)
	if err != nil {
		t.Fatal(err)
	}
	nm, _, _ := decode(key, id, next)
	if !reflect.DeepEqual(old, nm.RenewalTimings) || !reflect.DeepEqual(wait, nm.StagingProviderWait) {
		t.Fatal("timing intent/wait changed")
	}
	p, _, err := readTimingStatusAt(key, id, next, nm.Generation, fp, at.Add(time.Second))
	if err != nil || !p.Pending {
		t.Fatal("archive retired pending timing", err)
	}
	key, id, image, _ = exhaustedDNSFixture(t, false)
	image = fillArchiveHistory(t, key, id, image, minArchiveEvents)
	m, _, _ = decode(key, id, image)
	oldDNS := m.DNSPlans
	next, _, err = ArchiveHistory(key, id, image, m.Generation)
	if err != nil {
		t.Fatal(err)
	}
	nm, _, _ = decode(key, id, next)
	if !reflect.DeepEqual(oldDNS, nm.DNSPlans) {
		t.Fatal("DNS ownership/retry reset")
	}
	oldState, _ := openDNSPlan(key, id, m)
	state, _ := openDNSPlan(key, id, nm)
	if !reflect.DeepEqual(oldState, state) || state.Records[0].State != "creating" {
		t.Fatal("archive manufactured DNS result")
	}
}
