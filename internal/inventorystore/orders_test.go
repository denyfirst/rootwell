package inventorystore

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

const orderURLFixture = accountOrigin + "/acme/order/1234/5678"

func registeredOrderFixture(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	key, id, image, _ := preparedAccountFixture(t)
	pending, _, _, err := BeginStagingRegistration(key, id, image, 2, registrationTermsFixture)
	if err != nil {
		t.Fatal(err)
	}
	registered, _, _, err := FinishStagingRegistration(key, id, pending, 3, registrationURLFixture, false)
	if err != nil {
		t.Fatal(err)
	}
	return key, id, registered
}
func orderInstructionsFixture() acmeorder.Instructions {
	return acmeorder.Instructions{URL: orderURLFixture, Expires: time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05Z"), Records: []acmeorder.TXT{{Domain: "*.example.com", Name: "_acme-challenge.example.com", Value: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Required: true}, {Domain: "example.com", Name: "_acme-challenge.example.com", Value: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), Required: true}}}
}

func TestManualDNSOrderIntentCheckpointInstructionsAndLocalAcknowledgement(t *testing.T) {
	key, id, image := registeredOrderFixture(t)
	names := []string{"*.example.com", "example.com"}
	status, gen, err := ReadStagingOrder(key, id, image)
	if err != nil || gen != 4 || status.State != "not-started" {
		t.Fatal("registered legacy image failed")
	}
	pending, _, gen, err := BeginStagingOrder(key, id, image, 4, names)
	if err != nil || gen != 5 {
		t.Fatal("valid intent refused")
	}
	var outer envelope
	if !strictJSON(pending, &outer) {
		t.Fatal("invalid fixture envelope")
	}
	// Exact prior schema refuses the new field instead of silently dropping it.
	var prior struct {
		Version        int            `json:"version"`
		InstallationID []byte         `json:"installation_id"`
		Generation     uint64         `json:"generation"`
		Records        []sealedRecord `json:"records"`
		History        []sealedRecord `json:"history,omitempty"`
		Keys           []sealedRecord `json:"keys,omitempty"`
		Materials      []sealedRecord `json:"materials,omitempty"`
		ACMEAccounts   []sealedRecord `json:"acme_accounts,omitempty"`
	}
	if strictJSON(outer.Body, &prior) {
		t.Fatal("prior schema silently dropped order")
	}
	for _, secret := range []string{"example.com", "request-pending", registrationURLFixture} {
		if bytes.Contains(pending, []byte(secret)) {
			t.Fatal("order plaintext leaked")
		}
	}
	if next, _, _, err := BeginStagingOrder(key, id, pending, 5, names); err == nil || next != nil {
		t.Fatal("uncertain order recreated")
	}
	if next, _, _, err := UpdateStagingOrder(key, id, pending, 5, "", nil, true); err == nil || next != nil {
		t.Fatal("pending order acknowledged")
	}
	if err := WithStagingOrder(key, id, pending, 4, func(crypto.Signer, string, string, []string) error { t.Error("stale authority used"); return nil }); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("stale scope accepted")
	}
	err = WithStagingOrder(key, id, pending, 5, func(s crypto.Signer, account, order string, domains []string) error {
		if account != registrationURLFixture || order != "" || s == nil || len(domains) != 2 {
			t.Fatal("wrong sealed scope")
		}
		domains[0] = "evil.example.com"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	known, _, gen, err := UpdateStagingOrder(key, id, pending, 5, orderURLFixture, nil, false)
	if err != nil || gen != 6 {
		t.Fatal("checkpoint refused")
	}
	info := orderInstructionsFixture()
	ready, status, gen, err := UpdateStagingOrder(key, id, known, 6, "", &info, false)
	if err != nil || gen != 7 || status.State != "dns-ready" || len(status.Records) != 2 || status.Records[0].Value == status.Records[1].Value {
		t.Fatal("instructions collapsed/refused")
	}
	ack, status, gen, err := UpdateStagingOrder(key, id, ready, 7, "", nil, true)
	if err != nil || gen != 8 || status.State != "dns-acknowledged" {
		t.Fatal("local acknowledgement refused")
	}
	public, _ := json.Marshal(status)
	if bytes.Contains(public, []byte(orderURLFixture)) || bytes.Contains(public, []byte(registrationURLFixture)) || bytes.Contains(public, []byte("private_key")) {
		t.Fatal("public output released authority")
	}
	if _, _, _, err := UpdateStagingOrder(key, id, ack, 8, "", nil, true); err == nil {
		t.Fatal("ack replay accepted")
	}
	withCert, _, err := Append(key, id, ack, demo(t, "rootwell-demo-certificate.pem"), "team", "service")
	if err != nil {
		t.Fatal(err)
	}
	again, gen, err := ReadStagingOrder(key, id, withCert)
	if err != nil || gen != 9 || again.State != "dns-acknowledged" || len(again.Records) != 2 {
		t.Fatal("certificate write lost order")
	}
	old, _, _ := decode(key, id, image)
	next, _, _ := decode(key, id, withCert)
	if !bytes.Equal(old.ACMEAccounts[0].Ciphertext, next.ACMEAccounts[0].Ciphertext) {
		t.Fatal("order replaced account")
	}
	events, _, err := History(key, id, ack)
	if err != nil || len(events) != 7 || events[3].Action != "acme-order-started" || events[6].Action != "acme-dns-acknowledged" {
		t.Fatal("order history not atomic")
	}
	info.Expires = "2020-01-01T00:00:00Z"
	if _, _, _, err := UpdateStagingOrder(key, id, known, 6, "", &info, false); err == nil {
		t.Fatal("expired instructions accepted")
	}
}

func TestManualDNSOrderCorruptionRefusesAllOutputAndPurposeConfusion(t *testing.T) {
	key, id, image := registeredOrderFixture(t)
	pending, _, _, err := BeginStagingOrder(key, id, image, 4, []string{"*.example.com", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*manifest){func(m *manifest) { m.ACMEOrders = append(m.ACMEOrders, m.ACMEOrders[0]) }, func(m *manifest) { m.ACMEOrders[0].Ciphertext[30] ^= 1 }, func(m *manifest) { m.ACMEOrders[0].ID[0] ^= 1 }, func(m *manifest) { m.ACMEOrders[0].Generation = 1 }, func(m *manifest) { m.ACMEOrders[0].Generation = m.Generation + 1 }, func(m *manifest) { m.ACMEOrders[0].Ciphertext = make([]byte, 16385) }} {
		m, _, _ := decode(key, id, pending)
		change(&m)
		bad, _ := encode(key, m)
		if r, gen, err := Open(key, id, bad); err == nil || r != nil || gen != 0 {
			t.Fatal("corrupt order released certificates")
		}
		if s, gen, err := ReadStagingAccount(key, id, bad); err == nil || s.State != "" || gen != 0 {
			t.Fatal("corrupt order released account")
		}
		if s, gen, err := ReadStagingOrder(key, id, bad); err == nil || s.State != "" || gen != 0 {
			t.Fatal("corrupt order released instructions")
		}
	}
	m, _, _ := decode(key, id, pending)
	p, _ := openOrder(key, id, m)
	for _, change := range []func(*orderPayload){func(p *orderPayload) { p.State = "dns-ready" }, func(p *orderPayload) { p.Fingerprint = "wrong" }, func(p *orderPayload) { p.Started = "2020-01-01T00:00:00Z" }, func(p *orderPayload) { p.URL = orderURLFixture }, func(p *orderPayload) { p.Domains = []string{"example.com", "*.example.com"} }} {
		mut := p
		change(&mut)
		plain, _ := json.Marshal(mut)
		k, _ := orderKey(key, id)
		m.ACMEOrders[0].Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, m.ACMEOrders[0]), plain)
		clear(k)
		clear(plain)
		bad, _ := encode(key, m)
		if _, _, err := Open(key, id, bad); err == nil {
			t.Fatal("malformed sealed order accepted")
		}
	}
	plain, _ := json.Marshal(p)
	defer clear(plain)
	for _, k := range [][]byte{key, func() []byte { k, _ := accountKey(key, id); return k }()} {
		m.ACMEOrders[0].Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, m.ACMEOrders[0]), plain)
		bad, _ := encode(key, m)
		if _, _, err := Open(key, id, bad); err == nil {
			t.Fatal("wrong-purpose order opened")
		}
	}
}

func TestManualDNSOrderReservesCheckpointAndCompletionCapacity(t *testing.T) {
	key, id, image := registeredOrderFixture(t)
	m, _, _ := decode(key, id, image)
	status, _ := accountStatus(key, id, m)
	for len(m.History) < maxHistory-3 {
		m.Generation++
		if err := addEvent(key, &m, "import", []string{status.Fingerprint}); err != nil {
			t.Fatal(err)
		}
	}
	full, _ := encode(key, m)
	pending, _, gen, err := BeginStagingOrder(key, id, full, m.Generation, []string{"*.example.com", "example.com"})
	if err != nil {
		t.Fatal("reserved start refused")
	}
	pm, _, _ := decode(key, id, pending)
	pm.Generation++
	if err := addEvent(key, &pm, "import", []string{status.Fingerprint}); !errors.Is(err, ErrLimit) {
		t.Fatal("generic mutation consumed order reserve")
	}
	known, _, gen, err := UpdateStagingOrder(key, id, pending, gen, orderURLFixture, nil, false)
	if err != nil {
		t.Fatal("reserved checkpoint refused")
	}
	pm, _, _ = decode(key, id, known)
	pm.Generation++
	if err := addEvent(key, &pm, "import", []string{status.Fingerprint}); !errors.Is(err, ErrLimit) {
		t.Fatal("generic mutation consumed final reserve")
	}
	info := orderInstructionsFixture()
	if _, _, _, err := UpdateStagingOrder(key, id, known, gen, "", &info, false); err != nil {
		t.Fatal("reserved instructions refused")
	}
	m, _, _ = decode(key, id, image)
	m.Generation = maxGeneration - 3
	m.History = nil
	full, _ = encode(key, m)
	pending, _, gen, err = BeginStagingOrder(key, id, full, m.Generation, []string{"*.example.com", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	known, _, gen, err = UpdateStagingOrder(key, id, pending, gen, orderURLFixture, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, gen, err := UpdateStagingOrder(key, id, known, gen, "", &info, false); err != nil || gen != maxGeneration {
		t.Fatal("reserved generations failed")
	}
}

func TestManualDNSOrderPreservesSavedCertificateAndPrivateKey(t *testing.T) {
	key, id := testIdentity(t)
	image, _ := Create(key, id)
	cert, private, fp := generatedPair(t)
	defer clear(private)
	image, _, _, err := AppendMaterial(key, id, image, cert, private, nil, "team", "service", fp, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = PrepareStagingAccount(key, id, image, 2)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = BeginStagingRegistration(key, id, image, 3, registrationTermsFixture)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = FinishStagingRegistration(key, id, image, 4, registrationURLFixture, false)
	if err != nil {
		t.Fatal(err)
	}
	before, _, _ := decode(key, id, image)
	image, _, _, err = BeginStagingOrder(key, id, image, 5, []string{"*.example.com", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = UpdateStagingOrder(key, id, image, 6, orderURLFixture, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	info := orderInstructionsFixture()
	image, _, _, err = UpdateStagingOrder(key, id, image, 7, "", &info, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := WithCertificate(key, id, image, fp, 8, func(_ publicinventory.Record, k []byte) error {
		if !bytes.Equal(k, private) {
			t.Fatal("order changed certificate private key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	image, _, _, err = UpdateStagingOrder(key, id, image, 8, "", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = BeginStagingValidation(key, id, image, 9, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = FinishStagingValidation(key, id, image, 10, validationFixture())
	if err != nil {
		t.Fatal(err)
	}
	if err := WithCertificate(key, id, image, fp, 11, func(_ publicinventory.Record, k []byte) error {
		if !bytes.Equal(k, private) {
			t.Fatal("validation changed private key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after, _, _ := decode(key, id, image)
	if !bytes.Equal(before.Materials[0].Ciphertext, after.Materials[0].Ciphertext) || !bytes.Equal(before.Records[0].Ciphertext, after.Records[0].Ciphertext) || !bytes.Equal(before.ACMEAccounts[0].Ciphertext, after.ACMEAccounts[0].Ciphertext) {
		t.Fatal("order resealed unrelated certificate/account material")
	}
}

func FuzzManualDNSOrderPayload(f *testing.F) {
	key := bytes.Repeat([]byte{1}, 32)
	id := bytes.Repeat([]byte{2}, 16)
	image, err := Create(key, id)
	if err != nil {
		f.Fatal(err)
	}
	image, status, _, err := PrepareStagingAccount(key, id, image, 1)
	if err != nil {
		f.Fatal(err)
	}
	image, _, _, err = BeginStagingRegistration(key, id, image, 2, registrationTermsFixture)
	if err != nil {
		f.Fatal(err)
	}
	image, _, _, err = FinishStagingRegistration(key, id, image, 3, registrationURLFixture, false)
	if err != nil {
		f.Fatal(err)
	}
	seed := orderPayload{State: "request-pending", Fingerprint: status.Fingerprint, Started: time.Now().UTC().Format("2006-01-02T15:04:05Z"), Domains: []string{"*.example.com", "example.com"}}
	for _, state := range []string{"request-pending", "order-known", "dns-ready", "dns-acknowledged", "validation-pending", "validation-waiting", "domain-verified", "validation-failed"} {
		seed.State = state
		if state != "request-pending" {
			seed.URL = orderURLFixture
		}
		if state == "dns-ready" || state == "dns-acknowledged" || acmeorder.ValidationStarted(state) {
			info := orderInstructionsFixture()
			seed.Expires = info.Expires
			seed.Records = info.Records
		}
		if acmeorder.ValidationStarted(state) && state != "validation-pending" {
			v := acmeorder.Validation{URL: seed.URL, Expires: seed.Expires, OrderStatus: "ready", Statuses: []string{"valid", "valid"}}
			if state == "validation-waiting" {
				v.OrderStatus = "pending"
			}
			if state == "validation-failed" {
				v.OrderStatus = "invalid"
			}
			seed.Validation = &v
			seed.CheckedAt = seed.Started
		} else {
			seed.Validation = nil
			seed.CheckedAt = ""
		}
		raw, err := json.Marshal(seed)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte(`{"state":"request-pending","fingerprint":"invalid","started":"2026-10-11T00:00:00Z","domains":["example.com"]}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16384 {
			return
		}
		m, _, _ := decode(key, id, image)
		m.Generation++
		m.History = nil
		item := sealedRecord{ID: orderID(), Generation: m.Generation}
		k, _ := orderKey(key, id)
		item.Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, item), data)
		clear(k)
		m.ACMEOrders = []sealedRecord{item}
		bad, _ := encode(key, m)
		s, gen, err := ReadStagingOrder(key, id, bad)
		if err != nil && (s.State != "" || gen != 0) {
			t.Fatal("partial output")
		}
	})
}
