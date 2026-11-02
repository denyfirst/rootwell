package inventorystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
)

func TestProductionAccountSeparateEncryptedKeyAndSharedGeneration(t *testing.T) {
	key, id, image, staging := preparedAccountFixture(t)
	defer clear(key)
	old, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	next, status, gen, err := PrepareProductionAccount(key, id, image, old.Generation)
	if err != nil || gen != old.Generation+1 || status.State != "key-prepared" || status.Registration != "not-registered" || status.Fingerprint == staging.Fingerprint || status.PreparedAt == "" {
		t.Fatal("independent production key not prepared", err)
	}
	m, _, err := decode(key, id, next)
	if err != nil || !reflect.DeepEqual(m.ACMEAccounts, old.ACMEAccounts) || len(m.ProductionACMEAccounts) != 1 || len(m.Records) != len(old.Records) {
		t.Fatal("staging or library changed", err)
	}
	stageKey, err := accountKey(key, id)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(stageKey)
	prodKey, err := productionAccountKey(key, id)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(prodKey)
	if bytes.Equal(stageKey, prodKey) || bytes.Equal(key, prodKey) || bytes.Equal(accountID(), productionAccountID()) {
		t.Fatal("purpose separation missing")
	}
	item := m.ProductionACMEAccounts[0]
	if plain, err := inventoryseal.Open(stageKey, attachmentContext(id, item), item.Ciphertext); err == nil || plain != nil {
		t.Fatal("production ciphertext opened with staging key")
	}
	if raw, s, g, err := PrepareProductionAccount(key, id, next, gen); !errors.Is(err, ErrProductionAccountExists) || raw != nil || s != (AccountStatus{}) || g != 0 {
		t.Fatal("existing production key overwritten")
	}
	if raw, s, g, err := PrepareProductionAccount(key, id, image, old.Generation+1); !errors.Is(err, ErrStaleGeneration) || raw != nil || s != (AccountStatus{}) || g != 0 {
		t.Fatal("stale production preparation accepted")
	}
	got, g, err := ReadStagingAccount(key, id, next)
	if err != nil || got != staging || g != gen {
		t.Fatal("staging identity altered")
	}
	events, _, err := History(key, id, next)
	if err != nil || events[len(events)-1].Action != "acme-production-key-prepared" || events[len(events)-1].Fingerprints[0] != status.Fingerprint {
		t.Fatal("wrong production history", err)
	}
	// Generic mutations must keep the separate production key, with one shared
	// root generation. It is not a second vault or a separate quota counter.
	certificate := demo(t, "rootwell-demo-certificate.pem")
	appended, _, err := Append(key, id, next, certificate, "", "")
	if err != nil {
		t.Fatal(err)
	}
	got, g, err = ReadProductionAccount(key, id, appended)
	if err != nil || got != status || g != gen+1 {
		t.Fatal("generic write lost production key", err)
	}
}

func TestProductionAccountPreservesPendingStagingCompletionReserve(t *testing.T) {
	key, id, image, _ := preparedAccountFixture(t)
	defer clear(key)
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	m.Generation = maxGeneration - 2
	m.History = nil
	boundary, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	pending, _, gen, err := BeginStagingRegistration(key, id, boundary, m.Generation, registrationTermsFixture)
	if err != nil {
		t.Fatal(err)
	}
	if raw, status, g, err := PrepareProductionAccount(key, id, pending, gen); !errors.Is(err, ErrLimit) || raw != nil || status != (AccountStatus{}) || g != 0 {
		t.Fatal("production key consumed pending staging reserve", err)
	}
	if _, _, g, err := FinishStagingRegistration(key, id, pending, gen, registrationURLFixture, false); err != nil || g != maxGeneration {
		t.Fatal("staging completion reserve lost", err)
	}
	// The reverse creation order also has independent identities, no migration.
	empty, err := Create(key, id)
	if err != nil {
		t.Fatal(err)
	}
	prod, status, g, err := PrepareProductionAccount(key, id, empty, 1)
	if err != nil {
		t.Fatal(err)
	}
	stage, staging, g, err := PrepareStagingAccount(key, id, prod, g)
	if err != nil || g != 3 || staging.Fingerprint == status.Fingerprint {
		t.Fatal("reverse order mixed keys", err)
	}
	got, _, err := ReadProductionAccount(key, id, stage)
	if err != nil || got != status {
		t.Fatal("staging preparation replaced production key")
	}
}

func FuzzProductionAccountPayload(f *testing.F) {
	f.Add([]byte("null"))
	f.Add([]byte(`{"provider":"letsencrypt-staging","state":"registered"}`))
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		f.Fatal(err)
	}
	defer clear(private)
	seed, err := json.Marshal(productionAccountPayload{Provider: "letsencrypt-production", State: "key-prepared", PreparedAt: "2026-11-02T00:00:00Z", PrivateKey: private})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2048 {
			t.Skip()
		}
		key, id := testIdentity(t)
		defer clear(key)
		empty, err := Create(key, id)
		if err != nil {
			t.Fatal(err)
		}
		m, _, err := decode(key, id, empty)
		if err != nil {
			t.Fatal(err)
		}
		m.Generation = 2
		item := sealedRecord{ID: productionAccountID(), Generation: 2}
		k, err := productionAccountKey(key, id)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(k)
		item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), data)
		if len(data) == 0 {
			if !errors.Is(err, inventoryseal.ErrSize) || item.Ciphertext != nil {
				t.Fatal("empty plaintext was sealed")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		m.ProductionACMEAccounts = []sealedRecord{item}
		raw, err := encode(key, m)
		if err != nil {
			t.Fatal(err)
		}
		status, g, err := ReadProductionAccount(key, id, raw)
		if err != nil && (status != (AccountStatus{}) || g != 0) {
			t.Fatal("partial evidence on malformed payload")
		}
		if err == nil && (status.State != "key-prepared" || status.Registration != "not-registered" || len(status.Fingerprint) != 95 || g != 2) {
			t.Fatal("invented production account authority")
		}
	})
}

func TestProductionAccountCorruptionBlocksUnselectedScopeAndNoPartialEvidence(t *testing.T) {
	key, id, image, _ := preparedAccountFixture(t)
	defer clear(key)
	next, _, _, err := PrepareProductionAccount(key, id, image, 2)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := decode(key, id, next)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*manifest){
		"duplicate": func(v *manifest) {
			v.ProductionACMEAccounts = append(v.ProductionACMEAccounts, v.ProductionACMEAccounts[0])
		},
		"staging-substitution": func(v *manifest) { v.ProductionACMEAccounts = v.ACMEAccounts },
		"future-generation":    func(v *manifest) { v.ProductionACMEAccounts[0].Generation++ },
		"empty-ciphertext":     func(v *manifest) { v.ProductionACMEAccounts[0].Ciphertext = nil },
		"wrong-purpose-id":     func(v *manifest) { v.ProductionACMEAccounts[0].ID = accountID() },
		"ciphertext-tamper": func(v *manifest) {
			v.ProductionACMEAccounts[0].Ciphertext = bytes.Clone(v.ProductionACMEAccounts[0].Ciphertext)
			v.ProductionACMEAccounts[0].Ciphertext[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := m
			bad.ProductionACMEAccounts = append([]sealedRecord(nil), m.ProductionACMEAccounts...)
			mutate(&bad)
			raw, err := encode(key, bad)
			if err != nil {
				t.Fatal(err)
			}
			if records, gen, err := Open(key, id, raw); err == nil || records != nil || gen != 0 {
				t.Fatal("unselected production corruption ignored")
			}
			if status, gen, err := ReadStagingAccount(key, id, raw); err == nil || status != (AccountStatus{}) || gen != 0 {
				t.Fatal("staging read ignored production corruption")
			}
			if status, gen, err := ReadProductionAccount(key, id, raw); err == nil || status != (AccountStatus{}) || gen != 0 {
				t.Fatal("production read leaked partial evidence")
			}
		})
	}
	// Even correctly sealed production plaintext cannot smuggle an old staging
	// registration or unknown field into local-key-only custody.
	k, err := productionAccountKey(key, id)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(k)
	item := m.ProductionACMEAccounts[0]
	plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(plain, &fields); err != nil {
		t.Fatal(err)
	}
	fields["registration"] = json.RawMessage(`{"state":"registered"}`)
	changed, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(changed)
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), changed)
	if err != nil {
		t.Fatal(err)
	}
	m.ProductionACMEAccounts = []sealedRecord{item}
	raw, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(key, id, raw); err == nil {
		t.Fatal("production registration invented")
	}
}
