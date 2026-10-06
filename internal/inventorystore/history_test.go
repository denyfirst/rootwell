package inventorystore

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

func TestHistoryIsAtomicEncryptedCompleteAndRetainsDeletionIdentity(t *testing.T) {
	key, id := testIdentity(t)
	image, err := Create(key, id)
	if err != nil {
		t.Fatal(err)
	}
	cert := demo(t, "rootwell-demo-certificate.pem")
	image, records, err := Append(key, id, image, cert, "private-owner-marker", "private-location-marker")
	if err != nil {
		t.Fatal(err)
	}
	fp := records[0].Fingerprint
	if bytes.Contains(image, []byte("import")) || bytes.Contains(image, []byte(fp)) || bytes.Contains(image, []byte("private-owner-marker")) {
		t.Fatal("history or notes leaked")
	}
	image, _, _, err = UpdateOwner(key, id, image, fp, "new-owner", 2)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = AssociateLocation(key, id, image, fp, "other-server", 3)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = ChangeLocation(key, id, image, fp, "other-server", "renamed-server", LocationRename, 4)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = ChangeLocation(key, id, image, fp, "renamed-server", "", LocationRemove, 5)
	if err != nil {
		t.Fatal(err)
	}
	image, _, err = DeleteRecord(key, id, image, fp, 6)
	if err != nil {
		t.Fatal(err)
	}
	events, gen, err := History(key, id, image)
	want := []string{"import", "owner-changed", "location-added", "location-renamed", "location-removed", "record-deleted"}
	if err != nil || gen != 7 || len(events) != 6 {
		t.Fatalf("history: %v", err)
	}
	for i, event := range events {
		if event.Action != want[i] || event.Generation != uint64(i+2) || !slices.Equal(event.Fingerprints, []string{fp}) {
			t.Fatal("history mismatch")
		}
	}
	remaining, _, err := Open(key, id, image)
	if err != nil || len(remaining) != 0 {
		t.Fatal("deletion not committed with history")
	}
	before := bytes.Clone(image)
	if _, _, _, err := UpdateOwner(key, id, image, fp, "bad", 6); err == nil || !bytes.Equal(before, image) {
		t.Fatal("rejected mutation changed history")
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	m.History[0].Ciphertext[0] ^= 1
	corrupt, _ := encode(key, m)
	if records, _, err := Open(key, id, corrupt); err == nil || records != nil {
		t.Fatal("bad history exposed records")
	}
	if events, _, err := History(key, id, corrupt); err == nil || events != nil {
		t.Fatal("bad history exposed events")
	}
}

func TestHistoryLegacyBoundaryContinuityCapacityAndContext(t *testing.T) {
	key, id := testIdentity(t)
	image, _ := Create(key, id)
	image, records, err := Append(key, id, image, demo(t, "rootwell-demo-certificate.pem"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := decode(key, id, image)
	m.History = nil
	legacy, _ := encode(key, m)
	events, gen, err := History(key, id, legacy)
	if err != nil || gen != 2 || len(events) != 0 {
		t.Fatal("legacy image refused or history invented")
	}
	next, _, _, err := UpdateOwner(key, id, legacy, records[0].Fingerprint, "new", 2)
	if err != nil {
		t.Fatal(err)
	}
	events, _, err = History(key, id, next)
	if err != nil || len(events) != 1 || events[0].Generation != 3 {
		t.Fatal("legacy history start incorrect")
	}
	m, _, _ = decode(key, id, next)
	m.History[0].Generation = 2
	bad, _ := encode(key, m)
	if _, _, err := History(key, id, bad); err == nil {
		t.Fatal("event replay across generation accepted")
	}
	m, _, _ = decode(key, id, next)
	for len(m.History) < maxHistory {
		m.Generation++
		if err := addEvent(key, &m, "owner-changed", []string{records[0].Fingerprint}); err != nil {
			t.Fatal(err)
		}
	}
	full, _ := encode(key, m)
	if _, _, err := History(key, id, full); err != nil {
		t.Fatal("full valid history refused")
	}
	if output, _, _, err := UpdateOwner(key, id, full, records[0].Fingerprint, "another", m.Generation); !errors.Is(err, ErrLimit) || output != nil {
		t.Fatal("history silently truncated")
	}
	if len(m.History) != maxHistory {
		t.Fatal("capacity test changed input")
	}
}
