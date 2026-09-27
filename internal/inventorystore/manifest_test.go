package inventorystore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
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
	f.Add([]byte("bad"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxImage {
			return
		}
		_, _, _ = Open(key, id, data)
	})
}
