package inventorystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func preparedAccountFixture(t *testing.T) ([]byte, []byte, []byte, AccountStatus) {
	t.Helper()
	key, id := testIdentity(t)
	image, err := Create(key, id)
	if err != nil {
		t.Fatal(err)
	}
	next, status, gen, err := PrepareStagingAccount(key, id, image, 1)
	if err != nil || gen != 2 || status.State != "key-prepared" || status.PreparedAt == "" || len(status.Fingerprint) != 95 {
		t.Fatal("account key did not prepare")
	}
	return key, id, next, status
}

func accountPlainFixture(t *testing.T, key, id, image []byte) (manifest, accountPayload, []byte) {
	t.Helper()
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	k, err := accountKey(key, id)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := inventoryseal.Open(k, attachmentContext(id, m.ACMEAccounts[0]), m.ACMEAccounts[0].Ciphertext)
	clear(k)
	if err != nil {
		t.Fatal(err)
	}
	var p accountPayload
	if !strictJSON(plain, &p) {
		t.Fatal("fixture payload failed")
	}
	clear(plain)
	return m, p, bytes.Clone(p.PrivateKey)
}

func TestStagingAccountPreparationIsEncryptedAtomicAndPreserved(t *testing.T) {
	key, id := testIdentity(t)
	empty, err := Create(key, id)
	if err != nil {
		t.Fatal(err)
	}
	status, generation, err := ReadStagingAccount(key, id, empty)
	if err != nil || generation != 1 || status.State != "not-prepared" || status.Fingerprint != "" {
		t.Fatal("legacy empty image did not open")
	}
	if next, status, gen, err := PrepareStagingAccount(key, id, empty, 2); !errors.Is(err, ErrStaleGeneration) || next != nil || gen != 0 || status.State != "" {
		t.Fatal("stale preparation was accepted")
	}
	next, status, generation, err := PrepareStagingAccount(key, id, empty, 1)
	if err != nil || generation != 2 || status.State != "key-prepared" {
		t.Fatal("valid preparation refused")
	}
	m, p, private := accountPlainFixture(t, key, id, next)
	defer clear(p.PrivateKey)
	defer clear(private)
	for _, secret := range [][]byte{private, []byte(base64.StdEncoding.EncodeToString(private)), []byte("private_key"), []byte(status.Fingerprint)} {
		if bytes.Contains(next, secret) {
			t.Fatal("plaintext secret/metadata leaked in image")
		}
	}
	metadata, _ := json.Marshal(status)
	if bytes.Contains(metadata, []byte(base64.StdEncoding.EncodeToString(private))) || bytes.Contains(metadata, []byte("private_key")) {
		t.Fatal("metadata exposed signer")
	}
	// The saved material is a real signer, not fabricated public metadata.
	parsed, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		t.Fatal("stored signer invalid")
	}
	signer := parsed.(*ecdsa.PrivateKey)
	digest := sha256.Sum256([]byte("isolated account key proof"))
	sig, err := ecdsa.SignASN1(rand.Reader, signer, digest[:])
	if err != nil || !ecdsa.VerifyASN1(&signer.PublicKey, digest[:], sig) {
		t.Fatal("saved key cannot sign")
	}
	if result, _, _, err := PrepareStagingAccount(key, id, next, 2); !errors.Is(err, ErrAccountExists) || result != nil {
		t.Fatal("existing key replaced")
	}
	withCertificate, added, err := Append(key, id, next, demo(t, "rootwell-demo-certificate.pem"), "team", "service")
	if err != nil {
		t.Fatal(err)
	}
	withNotes, _, _, err := UpdateOwner(key, id, withCertificate, added[0].Fingerprint, "changed", 3)
	if err != nil {
		t.Fatal(err)
	}
	deleted, _, err := DeleteRecord(key, id, withNotes, added[0].Fingerprint, 4)
	if err != nil {
		t.Fatal(err)
	}
	again, gen, err := ReadStagingAccount(key, id, deleted)
	if err != nil || gen != 5 || again != status {
		t.Fatal("certificate mutation changed account")
	}
	mm, _, err := decode(key, id, deleted)
	if err != nil || !bytes.Equal(mm.ACMEAccounts[0].Ciphertext, m.ACMEAccounts[0].Ciphertext) {
		t.Fatal("certificate operation touched account ciphertext")
	}
	events, _, err := History(key, id, deleted)
	if err != nil || len(events) != 4 || events[0].Action != "acme-key-prepared" || events[0].Fingerprints[0] != status.Fingerprint {
		t.Fatal("account history not atomic")
	}
	// A previous binary's strict manifest schema refuses, rather than drops, it.
	var outer envelope
	if !strictJSON(next, &outer) {
		t.Fatal("fixture envelope")
	}
	var old struct {
		Version        int            `json:"version"`
		InstallationID []byte         `json:"installation_id"`
		Generation     uint64         `json:"generation"`
		Records        []sealedRecord `json:"records"`
		History        []sealedRecord `json:"history,omitempty"`
		Keys           []sealedRecord `json:"keys,omitempty"`
		Materials      []sealedRecord `json:"materials,omitempty"`
	}
	if strictJSON(outer.Body, &old) {
		t.Fatal("old schema silently dropped account")
	}
}

func TestStagingAccountTamperPurposeAndPayloadRefuseBeforeOutput(t *testing.T) {
	key, id, image, _ := preparedAccountFixture(t)
	for _, change := range []func(*manifest){
		func(m *manifest) { m.ACMEAccounts = append(m.ACMEAccounts, m.ACMEAccounts[0]) },
		func(m *manifest) { m.ACMEAccounts[0].Ciphertext[30] ^= 1 },
		func(m *manifest) { m.ACMEAccounts[0].ID[0] ^= 1 },
		func(m *manifest) { m.ACMEAccounts[0].Generation = 1 },
		func(m *manifest) { m.ACMEAccounts[0].Generation = m.Generation + 1 },
		func(m *manifest) { m.ACMEAccounts[0].Ciphertext = make([]byte, 2049) },
	} {
		m, _, _ := decode(key, id, image)
		change(&m)
		bad, _ := encode(key, m)
		if records, gen, err := Open(key, id, bad); err == nil || records != nil || gen != 0 {
			t.Fatal("bad account released certificate output")
		}
		if s, gen, err := ReadStagingAccount(key, id, bad); err == nil || s.State != "" || gen != 0 {
			t.Fatal("bad account released metadata")
		}
	}
	for _, change := range []func(*accountPayload){
		func(p *accountPayload) { p.Provider = "letsencrypt-production" }, func(p *accountPayload) { p.State = "registered" },
		func(p *accountPayload) { p.PreparedAt = "2026-02-30T00:00:00Z" }, func(p *accountPayload) { p.PreparedAt = "2019-01-01T00:00:00Z" },
		func(p *accountPayload) { p.PrivateKey = []byte("secret-sentinel") }, func(p *accountPayload) { p.PrivateKey = nil },
		func(p *accountPayload) { p.PrivateKey = make([]byte, 513) },
		func(p *accountPayload) {
			k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			p.PrivateKey, _ = x509.MarshalPKCS8PrivateKey(k)
		},
	} {
		m, p, private := accountPlainFixture(t, key, id, image)
		change(&p)
		plain, _ := json.Marshal(p)
		k, _ := accountKey(key, id)
		m.ACMEAccounts[0].Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, m.ACMEAccounts[0]), plain)
		bad, _ := encode(key, m)
		clear(k)
		clear(plain)
		clear(p.PrivateKey)
		clear(private)
		if records, _, err := Open(key, id, bad); err == nil || records != nil {
			t.Fatal("bad payload released output")
		}
	}
	m, p, private := accountPlainFixture(t, key, id, image)
	defer clear(p.PrivateKey)
	defer clear(private)
	plain, _ := json.Marshal(p)
	defer clear(plain)
	for _, wrongKey := range [][]byte{key, func() []byte { k, _ := attachmentKey(key, id, accountID()); return k }()} {
		m.ACMEAccounts[0].Ciphertext, _ = inventoryseal.Seal(wrongKey, attachmentContext(id, m.ACMEAccounts[0]), plain)
		bad, _ := encode(key, m)
		if _, _, err := Open(key, id, bad); err == nil {
			t.Fatal("wrong-purpose ciphertext opened")
		}
	}
	otherKey, otherID := testIdentity(t)
	if _, _, err := ReadStagingAccount(otherKey, otherID, image); err == nil {
		t.Fatal("cross-installation image opened")
	}
	m, _, _ = decode(key, id, image)
	m.InstallationID = otherID
	bad, _ := encode(key, m)
	if _, _, err := ReadStagingAccount(key, otherID, bad); err == nil {
		t.Fatal("authenticated ID swap opened account")
	}
}

func FuzzStagingAccountPayload(f *testing.F) {
	f.Add([]byte(`{"provider":"production","state":"registered","prepared_at":"bad","private_key":"AAAA"}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2048 {
			t.Skip()
		}
		key, id := testIdentity(t)
		image, _ := Create(key, id)
		m, _, _ := decode(key, id, image)
		m.Generation = 2
		item := sealedRecord{ID: accountID(), Generation: 2}
		k, _ := accountKey(key, id)
		item.Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, item), data)
		clear(k)
		m.ACMEAccounts = []sealedRecord{item}
		candidate, _ := encode(key, m)
		status, generation, err := ReadStagingAccount(key, id, candidate)
		if err != nil && (status.State != "" || generation != 0) {
			t.Fatal("partial account output")
		}
		if err == nil && (status.State != "key-prepared" || len(status.Fingerprint) != 95 || generation != 2) {
			t.Fatal("invalid capability")
		}
	})
}

func TestStagingAccountPreparationPreservesCertificateKeyCustody(t *testing.T) {
	for _, mode := range []string{"legacy-matched", "material-matched", "material-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			key, id := testIdentity(t)
			image, _ := Create(key, id)
			cert, private, fp := generatedPair(t)
			defer clear(private)
			if mode == "material-mismatch" {
				_, wrong, _ := generatedPair(t)
				clear(private)
				private = wrong
				defer clear(wrong)
			}
			var next []byte
			var err error
			if mode == "legacy-matched" {
				next, _, _, err = AppendCertificate(key, id, image, cert, private, nil, "team", "service", fp, 1)
			} else {
				next, _, _, err = AppendMaterial(key, id, image, cert, private, nil, "team", "service", fp, mode == "material-mismatch", 1)
			}
			if err != nil {
				t.Fatal(err)
			}
			prepared, account, gen, err := PrepareStagingAccount(key, id, next, 2)
			if err != nil || gen != 3 || account.State != "key-prepared" {
				t.Fatal("account preparation refused existing custody")
			}
			err = WithCertificate(key, id, prepared, fp, 3, func(r publicinventory.Record, k []byte) error {
				if !bytes.Equal(k, private) || r.Owner != "team" || r.Location != "service" || !r.HasPrivateKey || (r.KeyStatus == "mismatch") != (mode == "material-mismatch") {
					t.Fatal("account preparation changed certificate custody")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
