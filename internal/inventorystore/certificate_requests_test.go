package inventorystore

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
)

func verifiedCertificateRequestFixture(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	key, id, image := acknowledgedValidationFixture(t)
	pending, _, _, err := BeginStagingValidation(key, id, image, 8, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = FinishStagingValidation(key, id, pending, 9, validationFixture())
	if err != nil {
		t.Fatal(err)
	}
	return key, id, image
}
func requestPayloadFixture(t *testing.T, key, id []byte, m manifest) certificateRequestPayload {
	t.Helper()
	item := m.ACMECertificateRequests[0]
	k, err := certificateRequestKey(key, id)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(k)
	raw, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	var p certificateRequestPayload
	if !strictJSON(raw, &p) {
		t.Fatal("fixture request invalid")
	}
	return p
}
func requestRawImage(key, id []byte, m manifest, raw []byte) []byte {
	item := m.ACMECertificateRequests[0]
	k, _ := certificateRequestKey(key, id)
	defer clear(k)
	item.Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, item), raw)
	m.ACMECertificateRequests = []sealedRecord{item}
	image, _ := encode(key, m)
	return image
}

func TestCertificateRequestPreparationEncryptedBoundAtomicAndPreserved(t *testing.T) {
	key, id, image := verifiedCertificateRequestFixture(t)
	before, _, _ := decode(key, id, image)
	next, status, gen, err := PrepareStagingCertificateRequest(key, id, image, 10)
	if err != nil || gen != 11 || !status.Prepared || status.Fingerprint == "" || status.PreparedAt == "" {
		t.Fatal("valid request preparation refused")
	}
	after, _, _ := decode(key, id, next)
	for _, pair := range [][2][]byte{{before.ACMEAccounts[0].Ciphertext, after.ACMEAccounts[0].Ciphertext}, {before.ACMEOrders[0].Ciphertext, after.ACMEOrders[0].Ciphertext}} {
		if !bytes.Equal(pair[0], pair[1]) {
			t.Fatal("existing account/order changed")
		}
	}
	p := requestPayloadFixture(t, key, id, after)
	defer clear(p.PrivateKey)
	account, _ := accountStatus(key, id, after)
	if status.Fingerprint == account.Fingerprint || p.Order != orderURLFixture || !slices.Equal(p.Names, []string{"*.example.com", "example.com"}) {
		t.Fatal("account key/scope reused")
	}
	public, _ := json.Marshal(status)
	for _, secret := range [][]byte{p.PrivateKey, p.CSR, []byte(p.Order), []byte("private_key"), []byte("csr")} {
		if bytes.Contains(next, secret) || bytes.Contains(public, secret) {
			t.Fatal("secret/internal request leaked")
		}
	}
	if failed, s, g, err := PrepareStagingCertificateRequest(key, id, next, 11); err == nil || failed != nil || s.Prepared || g != 0 {
		t.Fatal("existing key replaced")
	}
	if _, _, _, err := PrepareStagingCertificateRequest(key, id, image, 9); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("stale preparation accepted")
	}
	added, _, err := Append(key, id, next, demo(t, "rootwell-demo-certificate.pem"), "owner", "service")
	if err != nil {
		t.Fatal(err)
	}
	restored, g, err := ReadStagingCertificateRequest(key, id, added)
	if err != nil || g != 12 || restored != status {
		t.Fatal("certificate mutation lost request")
	}
	events, _, err := History(key, id, added)
	if err != nil || events[len(events)-2].Action != "acme-certificate-key-prepared" || events[len(events)-2].Fingerprints[0] != status.Fingerprint {
		t.Fatal("history lost/secret")
	}
	// CA refresh may invalidate the domain observation, but not replace this key.
	refresh, _, _, err := BeginStagingValidation(key, id, added, 12, true)
	if err != nil {
		t.Fatal(err)
	}
	if s, _, err := ReadStagingCertificateRequest(key, id, refresh); err != nil || s != status {
		t.Fatal("refresh lost durable key")
	}
}

func TestCertificateRequestRefusesUnverifiedExpiredTamperedAndCrossPurpose(t *testing.T) {
	key, id, unverified := acknowledgedValidationFixture(t)
	if out, s, g, err := PrepareStagingCertificateRequest(key, id, unverified, 8); err == nil || out != nil || s.Prepared || g != 0 {
		t.Fatal("unverified request generated key")
	}
	key, id, image := verifiedCertificateRequestFixture(t)
	next, _, _, err := PrepareStagingCertificateRequest(key, id, image, 10)
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := decode(key, id, next)
	original := requestPayloadFixture(t, key, id, m)
	defer clear(original.PrivateKey)
	for _, mutate := range []func(*certificateRequestPayload){
		func(p *certificateRequestPayload) { p.State = "issued" }, func(p *certificateRequestPayload) { p.Order = accountOrigin + "/acme/order/1234/999" },
		func(p *certificateRequestPayload) { p.Names = []string{"evil.example.com"} }, func(p *certificateRequestPayload) { p.AccountFingerprint = "" },
		func(p *certificateRequestPayload) { p.PreparedAt = "2000-01-01T00:00:00Z" }, func(p *certificateRequestPayload) { p.PrivateKey = nil },
		func(p *certificateRequestPayload) { p.CSR = append(bytes.Clone(p.CSR), 0) },
	} {
		p := original
		mutate(&p)
		raw, _ := json.Marshal(p)
		bad := requestRawImage(key, id, m, raw)
		clear(raw)
		if out, g, err := ReadStagingCertificateRequest(key, id, bad); err == nil || g != 0 || out.Prepared {
			t.Fatal("authenticated bad scope/material returned authority")
		}
		if records, g, err := Open(key, id, bad); err == nil || records != nil || g != 0 {
			t.Fatal("other output escaped whole-image refusal")
		}
	}
	account, _ := openAccountPayload(key, id, m)
	defer clear(account.PrivateKey)
	parsed, _ := x509.ParsePKCS8PrivateKey(account.PrivateKey)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: original.Names}, parsed)
	p := original
	p.PrivateKey = account.PrivateKey
	p.CSR = csr
	raw, _ := json.Marshal(p)
	bad := requestRawImage(key, id, m, raw)
	clear(raw)
	if _, _, err := ReadStagingCertificateRequest(key, id, bad); err == nil {
		t.Fatal("account signer repurposed as certificate key")
	}
	for _, mutate := range []func(*manifest){
		func(m *manifest) {
			m.ACMECertificateRequests[0].Ciphertext = bytes.Clone(m.ACMECertificateRequests[0].Ciphertext)
			m.ACMECertificateRequests[0].Ciphertext[0] ^= 1
		},
		func(m *manifest) {
			m.ACMECertificateRequests = append(m.ACMECertificateRequests, m.ACMECertificateRequests[0])
		},
		func(m *manifest) { m.ACMECertificateRequests[0].Generation-- },
		func(m *manifest) { m.ACMECertificateRequests[0].ID = orderID() },
		func(m *manifest) { m.ACMECertificateRequests[0].Ciphertext = m.ACMEOrders[0].Ciphertext },
	} {
		copyM := m
		copyM.ACMECertificateRequests = slices.Clone(m.ACMECertificateRequests)
		mutate(&copyM)
		bad, _ := encode(key, copyM)
		if _, _, err := ReadStagingCertificateRequest(key, id, bad); err == nil {
			t.Fatal("context/purpose/tamper accepted")
		}
	}
	m, _, _ = decode(key, id, image)
	order, _ := openOrder(key, id, m)
	deadline, _ := time.Parse(time.RFC3339, order.Expires)
	if _, _, _, err := prepareStagingCertificateRequestAt(key, id, image, 10, deadline); err == nil {
		t.Fatal("exactly expired CA observation generated key")
	}
	checked, _ := time.Parse(time.RFC3339, order.CheckedAt)
	if _, _, _, err := prepareStagingCertificateRequestAt(key, id, image, 10, checked.Add(-time.Second)); err == nil {
		t.Fatal("clock before CA observation generated key")
	}
	m, _, _ = decode(key, id, image)
	m.Generation = maxGeneration
	m.History = nil // Valid legacy image with no event log, already at the nonce budget.
	atLimit, _ := encode(key, m)
	if _, _, _, err := PrepareStagingCertificateRequest(key, id, atLimit, maxGeneration); !errors.Is(err, ErrLimit) {
		t.Fatal("generation capacity not checked")
	}
	m, _, _ = decode(key, id, image)
	for len(m.History) < maxHistory {
		m.Generation++
		if err := addEvent(key, &m, "acme-validation-observed", []string{order.Fingerprint}); err != nil {
			t.Fatal(err)
		}
	}
	full, _ := encode(key, m)
	if out, s, g, err := PrepareStagingCertificateRequest(key, id, full, m.Generation); !errors.Is(err, ErrLimit) || out != nil || s.Prepared || g != 0 {
		t.Fatal("full history permitted key creation")
	}
}

func FuzzStagingCertificateRequestPayload(f *testing.F) {
	// Generated non-production fixture; no filesystem or CA traffic.
	key := bytes.Repeat([]byte{1}, 32)
	id := bytes.Repeat([]byte{2}, 16)
	image, err := Create(key, id)
	if err != nil {
		f.Fatal(err)
	}
	image, account, _, err := PrepareStagingAccount(key, id, image, 1)
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
	_ = account
	names := []string{"*.example.com", "example.com"}
	info := orderInstructionsFixture()
	image, _, _, err = BeginStagingOrder(key, id, image, 4, names)
	if err != nil {
		f.Fatal(err)
	}
	image, _, _, err = UpdateStagingOrder(key, id, image, 5, info.URL, nil, false)
	if err != nil {
		f.Fatal(err)
	}
	image, _, _, err = UpdateStagingOrder(key, id, image, 6, "", &info, false)
	if err != nil {
		f.Fatal(err)
	}
	image, _, _, err = UpdateStagingOrder(key, id, image, 7, "", nil, true)
	if err != nil {
		f.Fatal(err)
	}
	image, _, _, err = BeginStagingValidation(key, id, image, 8, false)
	if err != nil {
		f.Fatal(err)
	}
	image, _, _, err = FinishStagingValidation(key, id, image, 9, validationFixture())
	if err != nil {
		f.Fatal(err)
	}
	image, _, _, err = PrepareStagingCertificateRequest(key, id, image, 10)
	if err != nil {
		f.Fatal(err)
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		f.Fatal(err)
	}
	item := m.ACMECertificateRequests[0]
	k, _ := certificateRequestKey(key, id)
	defer clear(k)
	raw, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	if err != nil {
		f.Fatal(err)
	}
	defer clear(raw)
	f.Add(bytes.Clone(raw))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"state":"key-prepared","private_key":"sentinel"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			return
		}
		bad := requestRawImage(key, id, m, raw)
		s, g, err := ReadStagingCertificateRequest(key, id, bad)
		if err != nil && (s.Prepared || s.Fingerprint != "" || g != 0) {
			t.Fatal("invalid payload released partial authority")
		}
		if err == nil && (!s.Prepared || g != 11) {
			t.Fatal("valid payload lost preparation")
		}
	})
}
