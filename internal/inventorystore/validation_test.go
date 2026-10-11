package inventorystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
)

func acknowledgedValidationFixture(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	key, id, image := registeredOrderFixture(t)
	info := orderInstructionsFixture()
	var err error
	image, _, _, err = BeginStagingOrder(key, id, image, 4, []string{"*.example.com", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = UpdateStagingOrder(key, id, image, 5, info.URL, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = UpdateStagingOrder(key, id, image, 6, "", &info, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = UpdateStagingOrder(key, id, image, 7, "", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	return key, id, image
}
func validationFixture() acmeorder.Validation {
	return acmeorder.Validation{URL: orderURLFixture, Expires: time.Now().UTC().Add(30 * time.Minute).Format("2006-01-02T15:04:05Z"), OrderStatus: "ready", Statuses: []string{"valid", "valid"}}
}

func TestStagingValidationEncryptedIntentTruthPreservationAndNoReplay(t *testing.T) {
	key, id, image := acknowledgedValidationFixture(t)
	before, _, _ := decode(key, id, image)
	pending, status, gen, err := BeginStagingValidation(key, id, image, 8, false)
	if err != nil || gen != 9 || status.State != "validation-pending" {
		t.Fatal("intent refused")
	}
	if _, _, _, err := BeginStagingValidation(key, id, pending, 9, false); err == nil {
		t.Fatal("uncertain Accept replay authorized")
	}
	info := orderInstructionsFixture()
	if _, _, _, err := UpdateStagingOrder(key, id, pending, 9, "", &info, false); err == nil {
		t.Fatal("old preparation reset validation intent")
	}
	result := validationFixture()
	ready, status, gen, err := FinishStagingValidation(key, id, pending, 9, result)
	if err != nil || gen != 10 || status.State != "domain-verified" || len(status.Records) != 2 {
		t.Fatal("CA verdict refused")
	}
	after, _, _ := decode(key, id, ready)
	if !bytes.Equal(before.ACMEAccounts[0].Ciphertext, after.ACMEAccounts[0].Ciphertext) {
		t.Fatal("account signer replaced")
	}
	for _, secret := range []string{orderURLFixture, "domain-verified", "example.com", "order_status"} {
		if bytes.Contains(ready, []byte(secret)) {
			t.Fatal("validation plaintext leaked")
		}
	}
	result.Statuses[0] = "pending"
	if status, _, err := ReadStagingOrder(key, id, ready); err != nil || status.State != "domain-verified" {
		t.Fatal("caller mutated saved result")
	}
	if _, _, _, err := BeginStagingValidation(key, id, ready, 10, false); err == nil {
		t.Fatal("completed Accept replay authorized")
	}
	refresh, status, gen, err := BeginStagingValidation(key, id, ready, 10, true)
	if err != nil || gen != 11 || status.State != "validation-pending" {
		t.Fatal("refresh retained old success authority")
	}
	result = validationFixture()
	result.OrderStatus = "pending"
	if _, status, _, err := FinishStagingValidation(key, id, refresh, 11, result); err != nil || status.State != "validation-waiting" {
		t.Fatal("all valid alone falsely means ready")
	}
}

func TestStagingValidationRejectsStaleForeignExtendedMalformedAndTamperedResult(t *testing.T) {
	key, id, image := acknowledgedValidationFixture(t)
	if _, _, _, err := BeginStagingValidation(key, id, image, 7, false); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("stale intent accepted")
	}
	pending, _, _, _ := BeginStagingValidation(key, id, image, 8, false)
	for _, mutate := range []func(*acmeorder.Validation){func(v *acmeorder.Validation) { v.URL = accountOrigin + "/acme/order/1234/999" }, func(v *acmeorder.Validation) { v.Expires = "9999-01-01T00:00:00Z" }, func(v *acmeorder.Validation) { v.Statuses = v.Statuses[:1] }, func(v *acmeorder.Validation) { v.OrderStatus = "valid" }, func(v *acmeorder.Validation) { v.Statuses[0] = "pending" }} {
		v := validationFixture()
		mutate(&v)
		if next, status, gen, err := FinishStagingValidation(key, id, pending, 9, v); err == nil || next != nil || gen != 0 || status.State != "" {
			t.Fatal("foreign/extended/partial result accepted")
		}
	}
	ready, _, _, _ := FinishStagingValidation(key, id, pending, 9, validationFixture())
	m, _, _ := decode(key, id, ready)
	p, _ := openOrder(key, id, m)
	for _, mutate := range []func(*orderPayload){func(p *orderPayload) { p.Validation = nil }, func(p *orderPayload) { p.State = "dns-acknowledged" }, func(p *orderPayload) { p.CheckedAt = "2000-01-01T00:00:00Z" }, func(p *orderPayload) { p.Validation.Statuses[0] = "pending" }} {
		copyP := p
		v := *p.Validation
		v.Statuses = append([]string{}, v.Statuses...)
		copyP.Validation = &v
		mutate(&copyP)
		raw, _ := json.Marshal(copyP)
		k, _ := orderKey(key, id)
		item := m.ACMEOrders[0]
		item.Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, item), raw)
		clear(k)
		badM := m
		badM.ACMEOrders = []sealedRecord{item}
		bad, _ := encode(key, badM)
		if status, gen, err := ReadStagingOrder(key, id, bad); err == nil || gen != 0 || status.State != "" {
			t.Fatal("authenticated inconsistent validation output")
		}
	}
}

func TestStagingValidationReservesCompletionBeforeIO(t *testing.T) {
	key, id, image := acknowledgedValidationFixture(t)
	m, _, _ := decode(key, id, image)
	m.History = nil
	// Retain a valid bounded history, with exactly two slots for intent/result.
	for i := 0; i < maxHistory-2; i++ {
		m.Generation++
		if err := addEvent(key, &m, "acme-dns-acknowledged", []string{mFingerprint(t, key, id, m)}); err != nil {
			t.Fatal(err)
		}
	}
	image, _ = encode(key, m)
	pending, _, gen, err := BeginStagingValidation(key, id, image, m.Generation, false)
	if err != nil {
		t.Fatal("reserved intent refused")
	}
	pm, _, _ := decode(key, id, pending)
	pm.Generation++
	if err := addEvent(key, &pm, "acme-dns-acknowledged", []string{mFingerprint(t, key, id, pm)}); !errors.Is(err, ErrLimit) {
		t.Fatal("unrelated write stole result slot")
	}
	if _, _, _, err := FinishStagingValidation(key, id, pending, gen, validationFixture()); err != nil {
		t.Fatal("reserved completion lost")
	}
	if _, _, _, err := BeginStagingValidation(key, id, pending, gen, true); !errors.Is(err, ErrLimit) {
		t.Fatal("refresh lacked two slots")
	}
}
func mFingerprint(t *testing.T, key, id []byte, m manifest) string {
	t.Helper()
	p, err := openOrder(key, id, m)
	if err != nil {
		t.Fatal(err)
	}
	return p.Fingerprint
}
