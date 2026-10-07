package inventorystore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func TestMaterialMismatchAcknowledgementPreservationAndTamper(t *testing.T) {
	key, id := testIdentity(t)
	image, _ := Create(key, id)
	cert, private, fp := generatedPair(t)
	defer clear(private)
	_, wrong, _ := generatedPair(t)
	defer clear(wrong)
	for _, attempt := range []struct {
		private []byte
		ack     bool
	}{{wrong, false}, {private, true}, {[]byte("secret-sentinel"), true}} {
		bad, _, _, err := AppendMaterial(key, id, image, cert, attempt.private, nil, "", "", fp, attempt.ack, 1)
		if err == nil || len(bad) != 0 {
			t.Fatal("unacknowledged/malformed material accepted")
		}
	}
	next, r, gen, err := AppendMaterial(key, id, image, cert, wrong, nil, "", "Nginx", fp, true, 1)
	if err != nil || gen != 2 || r.KeyStatus != "mismatch" || !r.HasPrivateKey {
		t.Fatal("acknowledged loose attachment refused")
	}
	var borrowed []byte
	err = WithCertificate(key, id, next, fp, 2, func(record publicinventory.Record, k []byte) error {
		if record.KeyStatus != "mismatch" || !bytes.Equal(k, wrong) {
			t.Fatal("loose key identity/status changed")
		}
		borrowed = k
		return nil
	})
	if err != nil || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("loan not cleared")
	}
	listed, _, err := Open(key, id, next)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(listed)
	if bytes.Contains(public, []byte(base64.StdEncoding.EncodeToString(wrong))) || bytes.Contains(next, []byte(base64.StdEncoding.EncodeToString(wrong))) {
		t.Fatal("private key leaked")
	}
	changed, r, _, err := UpdateOwner(key, id, next, fp, "Team", 2)
	if err != nil || r.KeyStatus != "mismatch" {
		t.Fatal("note edit lost mismatch")
	}
	for _, mutation := range []func(*manifest){
		func(m *manifest) { m.Materials[0].Ciphertext[0] ^= 1 },
		func(m *manifest) { m.Materials[0].ID[0] ^= 1 },
		func(m *manifest) { m.Materials[0].Generation++ },
		func(m *manifest) { m.Materials = append(m.Materials, m.Materials[0]) },
		func(m *manifest) { m.Records = nil },
	} {
		m, _, err := decode(key, id, next)
		if err != nil {
			t.Fatal(err)
		}
		mutation(&m)
		bad, _ := encode(key, m)
		if records, gen, err := Open(key, id, bad); err == nil || len(records) != 0 || gen != 0 {
			t.Fatal("corrupt material returned metadata")
		}
	}
	// Even a newly sealed attachment may not lie about its acknowledgement.
	m, _, _ := decode(key, id, next)
	p, _ := openMaterial(key, id, m.Materials[0])
	defer clear(p.PrivateKey)
	p.MismatchAcknowledged = false
	plain, _ := json.Marshal(p)
	defer clear(plain)
	k, _ := materialKey(key, id, m.Materials[0].ID)
	defer clear(k)
	m.Materials[0].Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, m.Materials[0]), plain)
	bad, _ := encode(key, m)
	if _, _, err := Open(key, id, bad); err == nil {
		t.Fatal("false acknowledgement accepted")
	}
	deleted, _, err := DeleteRecord(key, id, changed, fp, 3)
	if err != nil {
		t.Fatal(err)
	}
	m, records, err := decode(key, id, deleted)
	if err != nil || len(records) != 0 || len(m.Materials) != 0 {
		t.Fatal("orphan after deletion")
	}
	if _, _, err := Open(key, id, next); err != nil {
		t.Fatal("earlier complete snapshot cannot restore loose attachment")
	}
}
