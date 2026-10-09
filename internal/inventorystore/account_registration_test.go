package inventorystore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
)

const registrationTermsFixture = "https://letsencrypt.org/documents/terms.pdf"
const registrationURLFixture = accountOrigin + "/acme/acct/1234"

func TestStagingRegistrationAtomicIntentSameSignerAndCompletion(t *testing.T) {
	key, id, image, original := preparedAccountFixture(t)
	if next, _, _, err := BeginStagingRegistration(key, id, image, 1, registrationTermsFixture); !errors.Is(err, ErrStaleGeneration) || next != nil {
		t.Fatal("stale registration was accepted")
	}
	if err := WithPendingStagingAccount(key, id, image, 2, func(crypto.Signer, string) error { t.Error("unapproved signer lent"); return nil }); err == nil {
		t.Fatal("prepared key gave registration authority")
	}
	pending, status, gen, err := BeginStagingRegistration(key, id, image, 2, registrationTermsFixture)
	if err != nil || gen != 3 || status.Registration != "registration-pending" || status.Fingerprint != original.Fingerprint {
		t.Fatal("valid intent refused")
	}
	for _, plain := range []string{registrationTermsFixture, "registration-pending", "private_key"} {
		if bytes.Contains(pending, []byte(plain)) {
			t.Fatal("intent leaked outside encryption")
		}
	}
	err = WithPendingStagingAccount(key, id, pending, 3, func(signer crypto.Signer, terms string) error {
		if terms != registrationTermsFixture {
			t.Fatal("accepted terms not bound")
		}
		digest := sha256.Sum256([]byte("isolated same account key proof"))
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil || !ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest[:], sig) {
			t.Fatal("pending account cannot sign")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if next, _, _, err := BeginStagingRegistration(key, id, pending, 3, registrationTermsFixture); err == nil || next != nil {
		t.Fatal("pending intent registered again")
	}
	if err := WithPendingStagingAccount(key, id, pending, 2, func(crypto.Signer, string) error { t.Error("stale signer used"); return nil }); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("stale signer accepted")
	}
	finished, ready, gen, err := FinishStagingRegistration(key, id, pending, 3, registrationURLFixture, false)
	if err != nil || gen != 4 || ready.Registration != "registered" || ready.Fingerprint != original.Fingerprint {
		t.Fatal("registration did not finish with same key")
	}
	if bytes.Contains(finished, []byte(registrationURLFixture)) {
		t.Fatal("account URL leaked in image")
	}
	_, oldPayload, oldKey := accountPlainFixture(t, key, id, image)
	defer clear(oldPayload.PrivateKey)
	defer clear(oldKey)
	_, newPayload, newKey := accountPlainFixture(t, key, id, finished)
	defer clear(newPayload.PrivateKey)
	defer clear(newKey)
	if !bytes.Equal(oldKey, newKey) || newPayload.Registration.AccountURL != registrationURLFixture {
		t.Fatal("completion replaced signer or lost account identity")
	}
	public, _ := json.Marshal(ready)
	if bytes.Contains(public, []byte(registrationURLFixture)) || bytes.Contains(public, []byte(registrationTermsFixture)) || bytes.Contains(public, []byte("private_key")) {
		t.Fatal("status released registration authority")
	}
	events, _, err := History(key, id, finished)
	if err != nil || len(events) != 3 || events[1].Action != "acme-registration-started" || events[2].Action != "acme-account-registered" {
		t.Fatal("intent/completion history not atomic")
	}
	if next, _, _, err := BeginStagingRegistration(key, id, finished, 4, registrationTermsFixture); err == nil || next != nil {
		t.Fatal("registered key replaced/reused for creation")
	}
	if err := WithPendingStagingAccount(key, id, finished, 4, func(crypto.Signer, string) error {
		t.Error("registered account received pending signer authority")
		return nil
	}); err == nil {
		t.Fatal("registered account signer released by pending-only API")
	}
}

func TestStagingRegistrationAbsentPreservesKeyAndCertificateMutations(t *testing.T) {
	key, id, image, original := preparedAccountFixture(t)
	pending, _, _, err := BeginStagingRegistration(key, id, image, 2, registrationTermsFixture)
	if err != nil {
		t.Fatal(err)
	}
	withCert, records, err := Append(key, id, pending, demo(t, "rootwell-demo-certificate.pem"), "team", "service")
	if err != nil {
		t.Fatal(err)
	}
	absent, status, gen, err := FinishStagingRegistration(key, id, withCert, 4, "", true)
	if err != nil || gen != 5 || status.Registration != "not-registered" || status.Fingerprint != original.Fingerprint {
		t.Fatal("confirmed absence lost key")
	}
	public, _, err := Open(key, id, absent)
	if err != nil || len(public) != 1 || public[0].Fingerprint != records[0].Fingerprint || public[0].Owner != "team" {
		t.Fatal("account completion lost certificate/notes")
	}
	if _, _, _, err := BeginStagingRegistration(key, id, absent, 5, registrationTermsFixture); err != nil {
		t.Fatal("explicit reattempt after absence refused")
	}
	for _, tc := range []struct {
		url    string
		absent bool
	}{{"http://127.0.0.1/acme/acct/1", false}, {registrationURLFixture + "?x=1", false}, {registrationURLFixture, true}, {"", false}} {
		if next, _, _, err := FinishStagingRegistration(key, id, pending, 3, tc.url, tc.absent); err == nil || next != nil {
			t.Fatal("malformed completion accepted")
		}
	}
}

func TestStagingRegistrationPayloadTamperRefusesBeforeAnyOutput(t *testing.T) {
	key, id, image, _ := preparedAccountFixture(t)
	pending, _, _, err := BeginStagingRegistration(key, id, image, 2, registrationTermsFixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*accountRegistration){
		func(r *accountRegistration) { r.State = "registered" }, func(r *accountRegistration) { r.Terms = "https://evil.invalid/terms.pdf" },
		func(r *accountRegistration) { r.StartedAt = "2019-01-01T00:00:00Z" }, func(r *accountRegistration) { r.StartedAt = "2026-02-30T00:00:00Z" },
		func(r *accountRegistration) { r.AccountURL = registrationURLFixture }, func(r *accountRegistration) { r.RegisteredAt = "2026-10-09T00:00:00Z" },
		func(r *accountRegistration) { r.State = "unchecked" },
	} {
		m, p, private := accountPlainFixture(t, key, id, pending)
		clear(private)
		change(p.Registration)
		plain, _ := json.Marshal(p)
		clear(p.PrivateKey)
		k, _ := accountKey(key, id)
		m.ACMEAccounts[0].Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, m.ACMEAccounts[0]), plain)
		clear(k)
		clear(plain)
		if err != nil {
			t.Fatal(err)
		}
		bad, err := encode(key, m)
		if err != nil {
			t.Fatal(err)
		}
		if records, _, err := Open(key, id, bad); err == nil || records != nil {
			t.Fatal("invalid registration released records")
		}
		if status, gen, err := ReadStagingAccount(key, id, bad); err == nil || status.State != "" || gen != 0 {
			t.Fatal("invalid registration released metadata")
		}
	}
}

func TestPendingRegistrationReservesHistoryAndGenerationForReconciliation(t *testing.T) {
	key, id, image, _ := preparedAccountFixture(t)
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := accountStatus(key, id, m)
	for len(m.History) < maxHistory-2 {
		m.Generation++
		if err := addEvent(key, &m, "import", []string{status.Fingerprint}); err != nil {
			t.Fatal(err)
		}
	}
	full, _ := encode(key, m)
	pending, _, generation, err := BeginStagingRegistration(key, id, full, m.Generation, registrationTermsFixture)
	if err != nil {
		t.Fatal("reservation rejected valid intent")
	}
	pm, _, _ := decode(key, id, pending)
	pm.Generation++
	if err := addEvent(key, &pm, "import", []string{status.Fingerprint}); !errors.Is(err, ErrLimit) {
		t.Fatal("generic mutation consumed last completion history slot")
	}
	if _, _, _, err := FinishStagingRegistration(key, id, pending, generation, registrationURLFixture, false); err != nil {
		t.Fatal("reserved history slot unavailable for completion")
	}
	m, _, _ = decode(key, id, image)
	m.Generation = maxGeneration - 2
	m.History = nil
	boundary, _ := encode(key, m)
	pending, _, generation, err = BeginStagingRegistration(key, id, boundary, m.Generation, registrationTermsFixture)
	if err != nil {
		t.Fatal("valid generation reservation refused")
	}
	pm, _, _ = decode(key, id, pending)
	pm.Generation++
	if err := addEvent(key, &pm, "import", []string{status.Fingerprint}); !errors.Is(err, ErrLimit) {
		t.Fatal("generic mutation consumed last completion generation")
	}
	if _, _, gen, err := FinishStagingRegistration(key, id, pending, generation, registrationURLFixture, false); err != nil || gen != maxGeneration {
		t.Fatal("reserved generation unavailable")
	}
}
