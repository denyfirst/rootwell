package inventorystore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/publicbundle"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func testIdentity(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, id := make([]byte, 32), make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return key, id
}

func demo(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../web/workbench/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCreateAppendOpenAndRejectDuplicate(t *testing.T) {
	key, id := testIdentity(t)
	image, err := Create(key, id)
	if err != nil {
		t.Fatal(err)
	}
	initial, gen, err := Open(key, id, image)
	if err != nil || len(initial) != 0 || gen != 1 {
		t.Fatalf("empty image: %d %d %v", len(initial), gen, err)
	}
	leaf := demo(t, "rootwell-demo-certificate.pem")
	next, added, err := Append(key, id, image, leaf, "Platform", "production/nginx")
	if err != nil || len(added) != 1 || added[0].ImportGeneration != 2 || added[0].ImportedAt == "" {
		t.Fatalf("append: %v", err)
	}
	if bytes.Contains(next, []byte("production/nginx")) || bytes.Contains(next, []byte("Platform")) {
		t.Fatal("metadata leaked in image")
	}
	if _, _, err := Append(key, id, next, leaf, "", ""); !errors.Is(err, publicinventory.ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	stored, gen, err := Open(key, id, next)
	if err != nil || gen != 2 || len(stored) != 1 || stored[0].Owner != "Platform" || stored[0].Location != "production/nginx" || stored[0].ImportGeneration != 2 || stored[0].ImportedAt != added[0].ImportedAt {
		t.Fatalf("open: %v %d %#v", err, gen, stored)
	}
	if _, err := time.Parse(time.RFC3339, stored[0].ImportedAt); err != nil {
		t.Fatalf("invalid save time: %v", err)
	}
	nextBatch, addedRoot, err := Append(key, id, next, demo(t, "rootwell-verify-demo-root.pem"), "CA team", "")
	if err != nil || len(addedRoot) != 1 || addedRoot[0].ImportGeneration != 3 {
		t.Fatalf("second import: %v", err)
	}
	ordered, third, err := Open(key, id, nextBatch)
	if err != nil || third != 3 || len(ordered) != 2 || ordered[0].ImportGeneration != 2 || ordered[1].ImportGeneration != 3 {
		t.Fatalf("import order lost: %v", err)
	}
	stored[0].DER[0] ^= 0xff
	again, _, err := Open(key, id, next)
	if err != nil || bytes.Equal(again[0].DER, stored[0].DER) {
		t.Fatal("open returned mutable backing storage")
	}
}

func TestOlderImageWithoutImportTimeStillOpens(t *testing.T) {
	key, id := testIdentity(t)
	parsed, err := publicbundle.Parse(demo(t, "rootwell-demo-certificate.pem"))
	if err != nil {
		t.Fatal(err)
	}
	der := parsed[0].DER
	plain, err := json.Marshal(payload{DER: der, Owner: "legacy", Location: ""})
	if err != nil {
		t.Fatal(err)
	}
	var install [16]byte
	copy(install[:], id)
	digest := sha256.Sum256(der)
	sealed, err := inventoryseal.Seal(key, inventoryseal.Context{InstallationID: install, RecordID: digest, Generation: 2}, plain)
	if err != nil {
		t.Fatal(err)
	}
	image, err := encode(key, manifest{Version: 1, InstallationID: id, Generation: 2, Records: []sealedRecord{{ID: digest[:], Generation: 2, Ciphertext: sealed}}})
	if err != nil {
		t.Fatal(err)
	}
	records, gen, err := Open(key, id, image)
	if err != nil || gen != 2 || len(records) != 1 || records[0].ImportedAt != "" || records[0].ImportGeneration != 2 {
		t.Fatalf("older image rejected: %v", err)
	}
	updated, record, generation, err := AssociateLocation(key, id, image, records[0].Fingerprint, "legacy/server", 2)
	if err != nil || generation != 3 || record.Location != "legacy/server" || record.ImportGeneration != 2 || record.ImportedAt != "" {
		t.Fatalf("older image association: %v", err)
	}
	reopened, _, err := Open(key, id, updated)
	if err != nil || len(reopened) != 1 || !slices.Equal(reopened[0].Locations, []string{"legacy/server"}) {
		t.Fatalf("older image did not migrate safely: %v", err)
	}
}

func TestAssociateLocationPreservesOneCertificateAndImportProvenance(t *testing.T) {
	key, id := testIdentity(t)
	image, err := Create(key, id)
	if err != nil {
		t.Fatal(err)
	}
	image, added, err := Append(key, id, image, demo(t, "rootwell-demo-certificate.pem"), "Platform", "production/nginx")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := added[0].Fingerprint
	importedAt := added[0].ImportedAt
	updatedImage, updated, generation, err := AssociateLocation(key, id, image, fingerprint, "production/haproxy", 2)
	if err != nil || generation != 3 || updated.ImportGeneration != 2 || updated.ImportedAt != importedAt ||
		!slices.Equal(updated.Locations, []string{"production/nginx", "production/haproxy"}) {
		t.Fatalf("first association: %v %#v", err, updated)
	}
	if bytes.Contains(updatedImage, []byte("production/haproxy")) || bytes.Contains(updatedImage, []byte("Platform")) {
		t.Fatal("associated metadata leaked from encrypted image")
	}
	if result, _, _, err := AssociateLocation(key, id, image, fingerprint, "stale/tab", 3); !errors.Is(err, ErrStaleGeneration) || result != nil {
		t.Fatalf("stale image generation accepted: %v", err)
	}
	for _, tc := range []struct {
		fingerprint, location string
		generation            uint64
		want                  error
	}{
		{fingerprint, "production/haproxy", 3, publicinventory.ErrLocationDuplicate},
		{"absent", "new/location", 3, ErrNotFound},
		{fingerprint, "bad\nlocation", 3, publicinventory.ErrLabel},
		{fingerprint, "valid/location", 2, ErrStaleGeneration},
	} {
		if result, _, _, err := AssociateLocation(key, id, updatedImage, tc.fingerprint, tc.location, tc.generation); !errors.Is(err, tc.want) || result != nil {
			t.Fatalf("unsafe association accepted: %v", err)
		}
	}
	opened, current, err := Open(key, id, updatedImage)
	if err != nil || current != 3 || len(opened) != 1 || opened[0].ImportGeneration != 2 ||
		!bytes.Equal(opened[0].DER, added[0].DER) || !slices.Equal(opened[0].Locations, updated.Locations) {
		t.Fatalf("updated image lost certificate or provenance: %v", err)
	}
	thirdImage, third, current, err := AssociateLocation(key, id, updatedImage, fingerprint, "staging/nginx", 3)
	if err != nil || current != 4 || third.ImportGeneration != 2 || len(third.Locations) != 3 {
		t.Fatalf("third location: %v", err)
	}
	opened, current, err = Open(key, id, thirdImage)
	if err != nil || current != 4 || len(opened) != 1 || opened[0].ImportGeneration != 2 || len(opened[0].Locations) != 3 {
		t.Fatalf("reopened locations: %v", err)
	}
	opened[0].Locations[0] = "mutated"
	again, _, err := Open(key, id, thirdImage)
	if err != nil || again[0].Locations[0] != "production/nginx" {
		t.Fatal("open returned mutable location storage")
	}
	withAnotherCert, addedOther, err := Append(key, id, thirdImage, demo(t, "rootwell-verify-demo-root.pem"), "CA team", "ca/vault")
	if err != nil || len(addedOther) != 1 || addedOther[0].ImportGeneration != 5 {
		t.Fatalf("later certificate import: %v", err)
	}
	afterImport, generation, err := Open(key, id, withAnotherCert)
	if err != nil || generation != 5 || len(afterImport) != 2 || len(afterImport[0].Locations) != 3 || afterImport[0].ImportGeneration != 2 {
		t.Fatalf("later import lost existing associations: %v", err)
	}
}

func TestAssociatedImageRejectsAuthorizedMalformedLocationPayload(t *testing.T) {
	key, id := testIdentity(t)
	image, _ := Create(key, id)
	image, added, _ := Append(key, id, image, demo(t, "rootwell-demo-certificate.pem"), "", "first")
	image, _, _, _ = AssociateLocation(key, id, image, added[0].Fingerprint, "second", 2)
	var outer envelope
	if err := json.Unmarshal(image, &outer); err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(outer.Body, &m); err != nil {
		t.Fatal(err)
	}
	var install [16]byte
	var recordID [32]byte
	copy(install[:], id)
	copy(recordID[:], m.Records[0].ID)
	plain, err := inventoryseal.Open(key, inventoryseal.Context{InstallationID: install, RecordID: recordID, Generation: m.Records[0].Generation}, m.Records[0].Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	var original payload
	if err := json.Unmarshal(plain, &original); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*payload){
		func(p *payload) { p.AdditionalLocations = []string{"first"} },
		func(p *payload) { p.AdditionalLocations = []string{"bad\nlocation"} },
		func(p *payload) { p.Location = "" },
		func(p *payload) { p.ImportGeneration = 1 },
		func(p *payload) { p.ImportGeneration = 4 },
	} {
		copyP := original
		mutate(&copyP)
		malformed, err := json.Marshal(copyP)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext, err := inventoryseal.Seal(key, inventoryseal.Context{InstallationID: install, RecordID: recordID, Generation: m.Records[0].Generation}, malformed)
		if err != nil {
			t.Fatal(err)
		}
		bad := m
		bad.Records = []sealedRecord{{ID: m.Records[0].ID, Generation: m.Records[0].Generation, Ciphertext: ciphertext}}
		badImage, err := encode(key, bad)
		if err != nil {
			t.Fatal(err)
		}
		if records, _, err := Open(key, id, badImage); err == nil || records != nil {
			t.Fatal("authorized but inconsistent location payload opened")
		}
	}
}

func TestCorruptionContextAndMalformedImportFailClosed(t *testing.T) {
	key, id := testIdentity(t)
	image, err := Create(key, id)
	if err != nil {
		t.Fatal(err)
	}
	image, _, err = Append(key, id, image, demo(t, "rootwell-demo-certificate.pem"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	otherKey, otherID := testIdentity(t)
	for _, tc := range []struct {
		name           string
		key, id, image []byte
	}{
		{"wrong key", otherKey, id, image}, {"wrong installation", key, otherID, image},
		{"truncated", key, id, image[:len(image)-1]}, {"trailing", key, id, append(bytes.Clone(image), 'x')},
		{"oversized", key, id, bytes.Repeat([]byte{'x'}, maxImage+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if records, _, err := Open(tc.key, tc.id, tc.image); err == nil || records != nil {
				t.Fatal("unsafe image opened")
			}
		})
	}
	changed := bytes.Clone(image)
	changed[len(changed)/2] ^= 1
	if records, _, err := Open(key, id, changed); err == nil || records != nil {
		t.Fatal("tampered image opened")
	}
	var outer envelope
	if err := json.Unmarshal(image, &outer); err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(outer.Body, &m); err != nil {
		t.Fatal(err)
	}
	m.Generation++ // old records still decrypt; only the manifest MAC detects this
	outer.Body, _ = json.Marshal(m)
	manifestTamper, _ := json.Marshal(outer)
	if records, _, err := Open(key, id, manifestTamper); err == nil || records != nil {
		t.Fatal("unauthenticated manifest generation accepted")
	}
	for _, input := range [][]byte{[]byte("bad"), []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")} {
		if result, added, err := Append(key, id, image, input, "", ""); err == nil || result != nil || added != nil {
			t.Fatal("unsafe import changed image")
		}
	}
	if records, _, err := Open(key, id, image); err != nil || len(records) != 1 {
		t.Fatal("rejected import mutated source")
	}
}

func TestManifestRejectsAuthorizedButInconsistentRecord(t *testing.T) {
	key, id := testIdentity(t)
	image, _ := Create(key, id)
	image, _, _ = Append(key, id, image, demo(t, "rootwell-demo-certificate.pem"), "", "")
	var outer envelope
	if err := json.Unmarshal(image, &outer); err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(outer.Body, &m); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*manifest){
		func(m *manifest) { m.Generation = 1 },
		func(m *manifest) { m.Records = append(m.Records, m.Records[0]) },
		func(m *manifest) { m.Records[0].ID[0] ^= 1 },
		func(m *manifest) { m.Records[0].Generation++ },
	} {
		var copyM manifest
		body, _ := json.Marshal(m)
		_ = json.Unmarshal(body, &copyM)
		mutate(&copyM)
		bad, err := encode(key, copyM)
		if err != nil {
			t.Fatal(err)
		}
		if result, _, err := Open(key, id, bad); err == nil || result != nil {
			t.Fatal("inconsistent manifest accepted")
		}
	}
}

func FuzzOpenImage(f *testing.F) {
	key := bytes.Repeat([]byte{1}, 32)
	id := bytes.Repeat([]byte{2}, 16)
	image, _ := Create(key, id)
	f.Add(image)
	fixture, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err == nil {
		withCert, added, err := Append(key, id, image, fixture, "", "first")
		if err == nil {
			withLocation, _, _, err := AssociateLocation(key, id, withCert, added[0].Fingerprint, "second", 2)
			if err == nil {
				f.Add(withLocation)
			}
		}
	}
	f.Add([]byte("bad"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxImage {
			return
		}
		_, _, _ = Open(key, id, data)
	})
}
