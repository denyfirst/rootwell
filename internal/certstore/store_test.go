package certstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/publicinventory"
	"github.com/denyfirst/rootwell/internal/vault"
)

type issued struct {
	certificate []byte // PEM, leaf then issuer
	key         []byte // PKCS #8 PEM
	fingerprint string
}

// issue makes a leaf for name under a fresh issuer.
func issue(t *testing.T, name string) issued {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name + " issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	records, err := certificatepair.Analyze(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), nil, nil)
	if err != nil || len(records) != 1 {
		t.Fatalf("fingerprint: %v", err)
	}
	return issued{
		certificate: append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...),
		key:         pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		fingerprint: records[0].Fingerprint,
	}
}

func newStore(t *testing.T) (*Store, *vault.Store) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the vault opens only in a private Linux directory")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := vault.NewInstanceKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Create(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return New(v), v
}

func TestSaveListsTheCertificateAndRefusesAStalePageOrADuplicate(t *testing.T) {
	s, _ := newStore(t)
	records, generation, err := s.List()
	if err != nil || len(records) != 0 || generation != 1 {
		t.Fatalf("empty list: %d records at %d: %v", len(records), generation, err)
	}
	a := issue(t, "a.example")
	saved, next, err := s.Save(1, a.certificate, nil, nil, "Platform team", "web-1", a.fingerprint, false)
	if err != nil || next != 2 || saved.Fingerprint != a.fingerprint || saved.HasPrivateKey || saved.KeyStatus != "not-added" ||
		len(saved.BundleDER) != 2 || saved.Owner != "Platform team" || saved.Location != "web-1" || saved.ImportGeneration != 2 {
		t.Fatalf("saved %+v at %d: %v", saved, next, err)
	}
	records, generation, err = s.List()
	if err != nil || generation != 2 || len(records) != 1 || records[0].Fingerprint != a.fingerprint || records[0].ImportedAt == "" {
		t.Fatalf("list after save: %+v at %d: %v", records, generation, err)
	}
	if _, _, err := s.Save(1, issue(t, "b.example").certificate, nil, nil, "", "", "", false); err == nil {
		t.Fatal("a save without a chosen certificate was accepted")
	}
	b := issue(t, "b.example")
	if _, _, err := s.Save(1, b.certificate, nil, nil, "", "", b.fingerprint, false); !errors.Is(err, ErrStale) {
		t.Fatalf("a save from an older page: %v", err)
	}
	if _, _, err := s.Save(2, a.certificate, nil, nil, "", "", a.fingerprint, false); !errors.Is(err, publicinventory.ErrDuplicate) {
		t.Fatalf("a second copy: %v", err)
	}
	if _, generation, _ := s.List(); generation != 2 {
		t.Fatalf("a refused save counted a generation: %d", generation)
	}
}

func TestWritesOutsideTheListLeaveAnOpenPageCurrent(t *testing.T) {
	s, v := newStore(t)
	a := issue(t, "a.example")
	if _, _, err := s.Save(1, a.certificate, nil, nil, "", "", a.fingerprint, false); err != nil {
		t.Fatal(err)
	}
	// A sign-in writes its account record to the same vault.
	if err := v.Update(func(tx *vault.Tx) error {
		return tx.Put("account", v.Index("account", "ada"), []byte(`{"name":"ada"}`))
	}); err != nil {
		t.Fatal(err)
	}
	if _, generation, err := s.List(); err != nil || generation != 2 {
		t.Fatalf("another record moved the list: %d: %v", generation, err)
	}
	if _, next, err := s.SetOwner(2, a.fingerprint, "Platform team"); err != nil || next != 3 {
		t.Fatalf("a page read before the other write was refused: %d: %v", next, err)
	}
	if _, generation, err := s.List(); err != nil || generation != 3 {
		t.Fatalf("the list after its own change: %d: %v", generation, err)
	}
	// A damaged counter is refused, never read as a fresh list.
	if err := v.Update(func(tx *vault.Tx) error {
		return tx.Put(kindList, v.Index(kindList, "list"), []byte(`{"generation":0}`))
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.List(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a damaged counter was read: %v", err)
	}
}

func TestAKeyIsSavedApartAndOnlyALoanOpensIt(t *testing.T) {
	s, v := newStore(t)
	a := issue(t, "a.example")
	saved, generation, err := s.Save(1, a.certificate, a.key, nil, "", "", a.fingerprint, false)
	if err != nil || !saved.HasPrivateKey || saved.KeyStatus != "matched" {
		t.Fatalf("saved %+v: %v", saved, err)
	}
	var lent []byte
	if err := s.WithCertificate(generation, a.fingerprint, func(r publicinventory.Record, key []byte) error {
		lent = bytes.Clone(key)
		return nil
	}); err != nil || len(lent) == 0 {
		t.Fatalf("loan: %d bytes, %v", len(lent), err)
	}
	// A damaged key record leaves the list readable: listing never opens it.
	if err := v.Update(func(t *vault.Tx) error {
		return t.Put(kindKey, v.Index(kindCertificate, a.fingerprint), []byte("not a sealed key"))
	}); err != nil {
		t.Fatal(err)
	}
	if records, _, err := s.List(); err != nil || len(records) != 1 || !records[0].HasPrivateKey {
		t.Fatalf("the list opened the key record: %+v %v", records, err)
	}
	if err := s.WithCertificate(generation, a.fingerprint, func(publicinventory.Record, []byte) error { return nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a damaged key was lent: %v", err)
	}
}

func TestAMismatchedKeyNeedsTheAcknowledgementAndOnlyThen(t *testing.T) {
	s, _ := newStore(t)
	a, other := issue(t, "a.example"), issue(t, "other.example")
	if _, _, err := s.Save(1, a.certificate, other.key, nil, "", "", a.fingerprint, false); !errors.Is(err, certificatepair.ErrInvalid) {
		t.Fatalf("a mismatched key without acknowledgement: %v", err)
	}
	if _, _, err := s.Save(1, a.certificate, a.key, nil, "", "", a.fingerprint, true); !errors.Is(err, certificatepair.ErrInvalid) {
		t.Fatalf("an acknowledgement for a matching key: %v", err)
	}
	saved, generation, err := s.Save(1, a.certificate, other.key, nil, "", "", a.fingerprint, true)
	if err != nil || saved.KeyStatus != "mismatch" {
		t.Fatalf("acknowledged mismatch: %+v %v", saved, err)
	}
	if err := s.WithCertificate(generation, a.fingerprint, func(r publicinventory.Record, key []byte) error {
		if r.KeyStatus != "mismatch" || len(key) == 0 {
			return errors.New("not lent as a mismatch")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAKeyAddedLaterIsCheckedFirstAndNeverReplaced(t *testing.T) {
	s, _ := newStore(t)
	a := issue(t, "a.example")
	_, generation, err := s.Save(1, a.certificate, nil, nil, "", "", a.fingerprint, false)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := s.CheckKey(generation, a.fingerprint, a.key, nil)
	if err != nil || checked.KeyStatus != "matched" {
		t.Fatalf("check: %+v %v", checked, err)
	}
	if records, after, _ := s.List(); after != generation || records[0].HasPrivateKey {
		t.Fatal("a check wrote")
	}
	attached, next, err := s.AttachKey(generation, a.fingerprint, a.key, nil, false)
	if err != nil || next != generation+1 || !attached.HasPrivateKey || attached.KeyStatus != "matched" {
		t.Fatalf("attach: %+v %v", attached, err)
	}
	if _, _, err := s.AttachKey(next, a.fingerprint, issue(t, "other.example").key, nil, true); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("a second key: %v", err)
	}
	if _, err := s.CheckKey(next, a.fingerprint, a.key, nil); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("a check against a saved key: %v", err)
	}
	if _, _, err := s.AttachKey(next, "AA", a.key, nil, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown certificate: %v", err)
	}
}

func TestPlacesAndOwnerChangeOneAtATime(t *testing.T) {
	s, _ := newStore(t)
	a := issue(t, "a.example")
	_, g, err := s.Save(1, a.certificate, nil, nil, "", "", a.fingerprint, false)
	if err != nil {
		t.Fatal(err)
	}
	r, g, err := s.AddLocation(g, a.fingerprint, "web-1")
	if err != nil || r.Location != "web-1" {
		t.Fatalf("add: %+v %v", r, err)
	}
	r, g, err = s.AddLocation(g, a.fingerprint, "web-2")
	if err != nil || len(r.Locations) != 2 {
		t.Fatalf("second place: %+v %v", r, err)
	}
	if _, _, err := s.AddLocation(g, a.fingerprint, "web-2"); !errors.Is(err, publicinventory.ErrLocationDuplicate) {
		t.Fatalf("a repeated place: %v", err)
	}
	r, g, err = s.ChangeLocation(g, a.fingerprint, "web-1", "web-0", Rename)
	if err != nil || r.Location != "web-0" {
		t.Fatalf("rename: %+v %v", r, err)
	}
	r, g, err = s.ChangeLocation(g, a.fingerprint, "web-0", "", Remove)
	if err != nil || r.Location != "web-2" || len(r.Locations) != 1 {
		t.Fatalf("remove: %+v %v", r, err)
	}
	r, g, err = s.SetOwner(g, a.fingerprint, "Platform team")
	if err != nil || r.Owner != "Platform team" {
		t.Fatalf("owner: %+v %v", r, err)
	}
	if _, _, err := s.SetOwner(g, a.fingerprint, "Platform team"); !errors.Is(err, publicinventory.ErrOwnerUnchanged) {
		t.Fatalf("an unchanged owner: %v", err)
	}
	if _, _, err := s.SetOwner(g-1, a.fingerprint, "Someone else"); !errors.Is(err, ErrStale) {
		t.Fatalf("an owner from an older page: %v", err)
	}
	records, _, err := s.List()
	if err != nil || records[0].Owner != "Platform team" || records[0].Location != "web-2" {
		t.Fatalf("stored: %+v %v", records, err)
	}
}

func TestDeleteTakesTheKeyWithIt(t *testing.T) {
	s, v := newStore(t)
	a := issue(t, "a.example")
	_, g, err := s.Save(1, a.certificate, a.key, nil, "", "", a.fingerprint, false)
	if err != nil {
		t.Fatal(err)
	}
	if g, err = s.Delete(g, a.fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Delete(g, a.fingerprint); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second delete: %v", err)
	}
	_ = v.View(func(t2 *vault.Tx) error {
		certificates, _ := t2.IDs(kindCertificate)
		keys, _ := t2.IDs(kindKey)
		if len(certificates) != 0 || len(keys) != 0 {
			t.Errorf("left behind: %d certificates, %d keys", len(certificates), len(keys))
		}
		return nil
	})
}

func TestARecordMovedToAnotherCertificateIsRefused(t *testing.T) {
	s, v := newStore(t)
	a, b := issue(t, "a.example"), issue(t, "b.example")
	_, g, err := s.Save(1, a.certificate, nil, nil, "", "", a.fingerprint, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Save(g, b.certificate, nil, nil, "", "", b.fingerprint, false); err != nil {
		t.Fatal(err)
	}
	// Write a's record, sealed correctly, into b's slot.
	if err := v.Update(func(t *vault.Tx) error {
		plain, _, err := t.Get(kindCertificate, v.Index(kindCertificate, a.fingerprint))
		if err != nil {
			return err
		}
		return t.Put(kindCertificate, v.Index(kindCertificate, b.fingerprint), plain)
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.List(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a moved record was listed: %v", err)
	}
}

func TestTheListStopsAtItsLimit(t *testing.T) {
	s, v := newStore(t)
	// Fill the list with records the store wrote itself, then try one more.
	a := issue(t, "a.example")
	_, g, err := s.Save(1, a.certificate, nil, nil, "", "", a.fingerprint, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Update(func(t *vault.Tx) error {
		plain, _, err := t.Get(kindCertificate, v.Index(kindCertificate, a.fingerprint))
		if err != nil {
			return err
		}
		for i := 1; i < MaxCertificates; i++ {
			if err := t.Put(kindCertificate, "filler-"+big.NewInt(int64(i)).String(), plain); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The fillers went in beside the store, so the list's own count is unchanged.
	b := issue(t, "b.example")
	if _, _, err := s.Save(g, b.certificate, nil, nil, "", "", b.fingerprint, false); !errors.Is(err, ErrFull) {
		t.Fatalf("one past the limit: %v", err)
	}
}

func TestStoredRecordsHoldNoUnknownFields(t *testing.T) {
	s, v := newStore(t)
	a := issue(t, "a.example")
	if _, _, err := s.Save(1, a.certificate, nil, nil, "", "", a.fingerprint, false); err != nil {
		t.Fatal(err)
	}
	if err := v.Update(func(t *vault.Tx) error {
		id := v.Index(kindCertificate, a.fingerprint)
		plain, _, err := t.Get(kindCertificate, id)
		if err != nil {
			return err
		}
		var fields map[string]any
		if err := json.Unmarshal(plain, &fields); err != nil {
			return err
		}
		fields["extra"] = true
		changed, _ := json.Marshal(fields)
		return t.Put(kindCertificate, id, changed)
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.List(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a record with an unknown field was listed: %v", err)
	}
}
