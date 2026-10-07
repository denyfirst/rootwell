package inventorystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func generatedPair(t *testing.T) ([]byte, []byte, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("fixture key creation failed")
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "custody.rootwell.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal("fixture certificate creation failed")
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("fixture marshal failed")
	}
	r, canonical, err := certificatepair.Prepare(der, private, nil, "", "")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return der, private, r.Fingerprint
}

func TestCertificateKeyCustodyAtomicityPreservationAndDeletion(t *testing.T) {
	key, id := testIdentity(t)
	image, _ := Create(key, id)
	cert, private, fp := generatedPair(t)
	defer clear(private)
	next, record, generation, err := AppendCertificate(key, id, image, cert, private, nil, "Team", "Nginx", fp, 1)
	if err != nil || !record.HasPrivateKey || generation != 2 {
		t.Fatal("pair was not stored atomically")
	}
	var outer envelope
	if json.Unmarshal(next, &outer) != nil || bytes.Contains(outer.Body, []byte(base64.StdEncoding.EncodeToString(private))) {
		t.Fatal("plaintext private key leaked into image")
	}
	listed, gen, err := Open(key, id, next)
	if err != nil || gen != 2 || len(listed) != 1 || !listed[0].HasPrivateKey {
		t.Fatal("pair listing failed")
	}
	public, _ := json.Marshal(listed)
	if bytes.Contains(public, private) || bytes.Contains(public, []byte(base64.StdEncoding.EncodeToString(private))) {
		t.Fatal("key leaked in public records")
	}
	var borrowed []byte
	err = WithCertificate(key, id, next, fp, 2, func(r publicinventory.Record, k []byte) error {
		if !bytes.Equal(private, k) || !r.HasPrivateKey {
			t.Fatal("wrong key released")
		}
		borrowed = k
		return nil
	})
	if err != nil || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed key not cleared")
	}
	changed, r, gen, err := UpdateOwner(key, id, next, fp, "New team", 2)
	if err != nil || gen != 3 || !r.HasPrivateKey {
		t.Fatal("owner update lost key attachment")
	}
	changed, r, gen, err = AssociateLocation(key, id, changed, fp, "Exchange", 3)
	if err != nil || gen != 4 || !r.HasPrivateKey {
		t.Fatal("note update lost key attachment")
	}
	err = WithCertificate(key, id, changed, fp, 4, func(_ publicinventory.Record, k []byte) error {
		if !bytes.Equal(k, private) {
			t.Fatal("metadata correction changed key")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []uint64{0, 1, 3} {
		if err := WithCertificate(key, id, changed, fp, expected, func(_ publicinventory.Record, _ []byte) error { t.Fatal("stale callback invoked"); return nil }); err == nil {
			t.Fatal("stale release accepted")
		}
	}
	deleted, gen, err := DeleteRecord(key, id, changed, fp, 4)
	if err != nil || gen != 5 {
		t.Fatal("pair deletion failed")
	}
	m, records, err := decode(key, id, deleted)
	if err != nil || len(records) != 0 || len(m.Keys) != 0 {
		t.Fatal("orphan private key after deletion")
	}
	// The earlier complete image still contains the key: deletion is not erasure.
	if _, _, err := Open(key, id, next); err != nil {
		t.Fatal("earlier snapshot was unexpectedly invalidated")
	}
	_, wrong, _ := generatedPair(t)
	defer clear(wrong)
	for _, candidate := range [][]byte{wrong, []byte("private-sentinel-invalid")} {
		bad, _, _, err := AppendCertificate(key, id, image, cert, candidate, nil, "", "", fp, 1)
		if err == nil || len(bad) != 0 {
			t.Fatal("mismatch returned an installable image")
		}
	}
}

func TestAttachmentTamperAndIdentitySwapFailBeforeOutput(t *testing.T) {
	key, id := testIdentity(t)
	empty, _ := Create(key, id)
	c1, k1, f1 := generatedPair(t)
	defer clear(k1)
	first, _, _, err := AppendCertificate(key, id, empty, c1, k1, nil, "", "", f1, 1)
	if err != nil {
		t.Fatal(err)
	}
	c2, k2, f2 := generatedPair(t)
	defer clear(k2)
	image, _, _, err := AppendCertificate(key, id, first, c2, k2, nil, "", "", f2, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*manifest){
		func(m *manifest) { m.Keys[0].Ciphertext[len(m.Keys[0].Ciphertext)-1] ^= 1 },
		func(m *manifest) { m.Keys[0].ID, m.Keys[1].ID = m.Keys[1].ID, m.Keys[0].ID },
		func(m *manifest) { m.Keys[0].Generation++ },
		func(m *manifest) { m.Keys = append(m.Keys, m.Keys[0]) },
		func(m *manifest) { m.Records = m.Records[:1] },
	} {
		m, _, err := decode(key, id, image)
		if err != nil {
			t.Fatal(err)
		}
		mutation(&m)
		bad, _ := encode(key, m)
		if records, gen, err := Open(key, id, bad); err == nil || len(records) != 0 || gen != 0 {
			t.Fatal("tampered attachment returned public output")
		}
	}
}
