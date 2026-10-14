package inventorystore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
)

const configZoneID = "0123456789abcdef0123456789abcdef"
const configToken = "synthetic-only-credential-not-a-real-token-1234567890"

func cloudflareFixture(t *testing.T) ([]byte, []byte, []byte, CloudflareStatus) {
	t.Helper()
	key, id := testIdentity(t)
	image, _ := Create(key, id)
	next, status, gen, err := ChangeCloudflareConfig(key, id, image, 1, configZoneID, "example.com", []byte(configToken), false)
	if err != nil || gen != 2 || status.State != "saved" || status.ZoneName != "example.com" || !status.CanChange || status.SavedAt == "" {
		t.Fatal("legitimate encrypted credential refused")
	}
	return key, id, next, status
}

func TestCloudflareConfigEncryptedAtomicRotationRemovalAndPreservation(t *testing.T) {
	key, id, image, status := cloudflareFixture(t)
	meta, _ := json.Marshal(status)
	events, _, err := History(key, id, image)
	history, _ := json.Marshal(events)
	if err != nil || len(events) != 1 || events[0].Action != "dns-cloudflare-saved" {
		t.Fatal("configuration history missing")
	}
	for _, data := range [][]byte{image, meta, history} {
		for _, secret := range []string{configToken, base64.StdEncoding.EncodeToString([]byte(configToken)), configZoneID, "\"token\""} {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatal("credential leaked from encrypted image/status/history")
			}
		}
	}
	m, _, _ := decode(key, id, image)
	withCert, added, err := Append(key, id, image, demo(t, "rootwell-demo-certificate.pem"), "team", "service")
	if err != nil {
		t.Fatal(err)
	}
	withNotes, _, _, err := UpdateOwner(key, id, withCert, added[0].Fingerprint, "changed", 3)
	if err != nil {
		t.Fatal(err)
	}
	mm, _, err := decode(key, id, withNotes)
	if err != nil || !bytes.Equal(mm.CloudflareConfigs[0].Ciphertext, m.CloudflareConfigs[0].Ciphertext) {
		t.Fatal("certificate mutation changed credential")
	}
	rotated, _, gen, err := ChangeCloudflareConfig(key, id, withNotes, 4, configZoneID, "example.com", []byte(strings.Repeat("B", 40)), false)
	if err != nil || gen != 5 {
		t.Fatal("explicit rotation refused")
	}
	mm, _, _ = decode(key, id, rotated)
	p, err := openCloudflareConfig(key, id, mm)
	if err != nil || string(p.Token) != strings.Repeat("B", 40) {
		t.Fatal("rotation retained wrong credential")
	}
	clear(p.Token)
	removed, s, gen, err := ChangeCloudflareConfig(key, id, rotated, 5, "", "", nil, true)
	if err != nil || gen != 6 || s.State != "not-configured" || s.ZoneName != "" || !s.CanChange {
		t.Fatal("explicit removal refused")
	}
	mm, records, err := decode(key, id, removed)
	if err != nil || len(mm.CloudflareConfigs) != 0 || len(records) != 1 || records[0].Owner != "changed" {
		t.Fatal("removal damaged certificate")
	}
	// Existing binaries reject the new authenticated field, not silently drop it.
	var outer envelope
	_ = json.Unmarshal(image, &outer)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(outer.Body, &fields)
	if fields["cloudflare_configs"] == nil {
		t.Fatal("credential is not in complete image")
	}
	var old struct {
		Version        int            `json:"version"`
		InstallationID []byte         `json:"installation_id"`
		Generation     uint64         `json:"generation"`
		Records        []sealedRecord `json:"records"`
		History        []sealedRecord `json:"history,omitempty"`
	}
	if strictJSON(outer.Body, &old) {
		t.Fatal("old schema dropped credential")
	}
}

func TestCloudflareConfigMalformedTamperPurposeAndStaleRefuseBeforeOutput(t *testing.T) {
	key, id, image, _ := cloudflareFixture(t)
	if next, s, gen, err := ChangeCloudflareConfig(key, id, image, 1, configZoneID, "example.com", []byte(configToken), false); !errors.Is(err, ErrStaleGeneration) || next != nil || s.State != "" || gen != 0 {
		t.Fatal("stale configuration changed")
	}
	for _, change := range []func(*manifest){
		func(m *manifest) { m.CloudflareConfigs = append(m.CloudflareConfigs, m.CloudflareConfigs[0]) },
		func(m *manifest) { m.CloudflareConfigs[0].ID[0] ^= 1 },
		func(m *manifest) { m.CloudflareConfigs[0].Generation = 1 },
		func(m *manifest) { m.CloudflareConfigs[0].Generation = 3 },
		func(m *manifest) { m.CloudflareConfigs[0].Ciphertext[30] ^= 1 },
		func(m *manifest) { m.CloudflareConfigs[0].Ciphertext = make([]byte, 2049) },
	} {
		m, _, _ := decode(key, id, image)
		change(&m)
		bad, _ := encode(key, m)
		if records, gen, err := Open(key, id, bad); err == nil || records != nil || gen != 0 {
			t.Fatal("invalid credential released certificate metadata")
		}
		if s, gen, err := ReadCloudflareConfig(key, id, bad); err == nil || s.State != "" || gen != 0 {
			t.Fatal("invalid credential released status")
		}
	}
	for _, change := range []func(*cloudflarePayload){
		func(p *cloudflarePayload) { p.ZoneID = "../path" },
		func(p *cloudflarePayload) { p.ZoneName = "Example.com" },
		func(p *cloudflarePayload) { p.ZoneName = "*.example.com" },
		func(p *cloudflarePayload) { p.Token = []byte("sentinel\r\nAuthorization: other") },
		func(p *cloudflarePayload) { p.Token = nil },
		func(p *cloudflarePayload) { p.SavedAt = "2026-02-30T00:00:00Z" },
		func(p *cloudflarePayload) { p.SavedAt = "2101-01-01T00:00:00Z" },
	} {
		m, _, _ := decode(key, id, image)
		p, _ := openCloudflareConfig(key, id, m)
		change(&p)
		plain, _ := json.Marshal(p)
		k, _ := cloudflareConfigKey(key, id)
		m.CloudflareConfigs[0].Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, m.CloudflareConfigs[0]), plain)
		clear(k)
		clear(plain)
		clear(p.Token)
		bad, _ := encode(key, m)
		if records, _, err := Open(key, id, bad); err == nil || records != nil {
			t.Fatal("malformed credential released metadata")
		}
	}
	m, _, _ := decode(key, id, image)
	p, _ := openCloudflareConfig(key, id, m)
	plain, _ := json.Marshal(p)
	defer clear(p.Token)
	defer clear(plain)
	m.CloudflareConfigs[0].Ciphertext, _ = inventoryseal.Seal(key, attachmentContext(id, m.CloudflareConfigs[0]), plain)
	bad, _ := encode(key, m)
	if _, _, err := Open(key, id, bad); err == nil {
		t.Fatal("wrong-purpose ciphertext accepted")
	}
	other := bytes.Clone(id)
	other[0] ^= 1
	if _, _, err := ReadCloudflareConfig(key, other, image); err == nil {
		t.Fatal("cross-installation credential accepted")
	}
}

func TestCloudflareConfigActiveOrderBlocksRotationAndRemoval(t *testing.T) {
	key, id, image, _ := cloudflareFixture(t)
	// Real authenticated order fixture, not client-provided status.
	baseKey, baseID, registered := registeredOrderFixture(t)
	orderImage, _, _, err := BeginStagingOrder(baseKey, baseID, registered, 4, []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := decode(baseKey, baseID, orderImage)
	configured, _, gen, err := ChangeCloudflareConfig(baseKey, baseID, orderImage, m.Generation, configZoneID, "example.com", []byte(configToken), false)
	if err != nil {
		t.Fatal("first local configuration refused")
	}
	s, _, err := ReadCloudflareConfig(baseKey, baseID, configured)
	if err != nil || s.CanChange {
		t.Fatal("active order allowed credential change")
	}
	for _, remove := range []bool{false, true} {
		zoneID, zone, token := configZoneID, "example.com", []byte(configToken)
		if remove {
			zoneID, zone, token = "", "", nil
		}
		next, s, got, err := ChangeCloudflareConfig(baseKey, baseID, configured, gen, zoneID, zone, token, remove)
		if !errors.Is(err, ErrDNSConfigInUse) || next != nil || s.State != "" || got != 0 {
			t.Fatal("active request lost credential")
		}
	}
	// Refused malformed removal cannot become an implicit overwrite.
	if next, _, _, err := ChangeCloudflareConfig(key, id, image, 2, "", "", []byte(configToken), true); err == nil || next != nil {
		t.Fatal("ambiguous removal accepted")
	}
}

func TestCloudflareConfigPreservesPrivatePairAndPendingCompletionCapacity(t *testing.T) {
	key, id := testIdentity(t)
	image, _ := Create(key, id)
	cert, private, fp := generatedPair(t)
	defer clear(private)
	image, _, _, err := AppendMaterial(key, id, image, cert, private, nil, "team", "service", fp, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	before, _, _ := decode(key, id, image)
	next, _, _, err := ChangeCloudflareConfig(key, id, image, 2, configZoneID, "example.com", []byte(configToken), false)
	if err != nil {
		t.Fatal(err)
	}
	after, records, err := decode(key, id, next)
	if err != nil || len(records) != 1 || !records[0].HasPrivateKey || records[0].KeyStatus != "matched" || !bytes.Equal(before.Materials[0].Ciphertext, after.Materials[0].Ciphertext) {
		t.Fatal("configuration damaged private pair")
	}
	key, id, accountImage, _ := preparedAccountFixture(t)
	pending, _, _, err := BeginStagingRegistration(key, id, accountImage, 2, registrationTermsFixture)
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := decode(key, id, pending)
	m.History = nil
	m.Generation = maxGeneration - 1
	nearLimit, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	if next, s, gen, err := ChangeCloudflareConfig(key, id, nearLimit, maxGeneration-1, configZoneID, "example.com", []byte(configToken), false); !errors.Is(err, ErrLimit) || next != nil || s.State != "" || gen != 0 {
		t.Fatal("configuration consumed pending registration completion slot")
	}
	m.Generation = maxGeneration
	m.ACMEAccounts = nil
	exhausted, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	if next, _, _, err := ChangeCloudflareConfig(key, id, exhausted, maxGeneration, configZoneID, "example.com", []byte(configToken), false); !errors.Is(err, ErrLimit) || next != nil {
		t.Fatal("exhausted image accepted config")
	}
}

func FuzzCloudflareConfigurationPayload(f *testing.F) {
	seed, _ := json.Marshal(cloudflarePayload{ZoneID: configZoneID, ZoneName: "example.com", Token: []byte(configToken), SavedAt: "2026-10-14T00:00:00Z"})
	f.Add(seed)
	f.Add([]byte("null"))
	f.Add([]byte(`{"token":"c2VudGluZWw="}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2048 {
			t.Skip()
		}
		key, id := testIdentity(t)
		image, _ := Create(key, id)
		m, _, _ := decode(key, id, image)
		m.Generation = 2
		item := sealedRecord{ID: cloudflareConfigID(), Generation: 2}
		k, _ := cloudflareConfigKey(key, id)
		item.Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, item), data)
		clear(k)
		m.CloudflareConfigs = []sealedRecord{item}
		image, _ = encode(key, m)
		s, gen, err := ReadCloudflareConfig(key, id, image)
		if err != nil && (s.State != "" || gen != 0) {
			t.Fatal("partial output")
		}
		if err == nil && (s.State != "saved" || gen != 2 || !s.CanChange) {
			t.Fatal("invalid status")
		}
	})
}
