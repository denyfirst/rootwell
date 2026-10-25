package inventorystore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/denyfirst/rootwell/internal/acmeorder"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

func dnsPlanFixture(t testing.TB) ([]byte, []byte, []byte) {
	t.Helper()
	key, id, image := registeredOrderFixture(t)
	next, _, _, err := BeginStagingOrder(key, id, image, 4, []string{"*.example.com", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	next, _, _, err = UpdateStagingOrder(key, id, next, 5, orderURLFixture, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	info := orderInstructionsFixture()
	next, _, _, err = UpdateStagingOrder(key, id, next, 6, "", &info, false)
	if err != nil {
		t.Fatal(err)
	}
	next, _, _, err = ChangeCloudflareConfig(key, id, next, 7, configZoneID, "example.com", []byte(configToken), false)
	if err != nil {
		t.Fatal(err)
	}
	return key, id, next
}
func preparedDNSPlanFixture(t testing.TB) ([]byte, []byte, []byte) {
	t.Helper()
	key, id, image := dnsPlanFixture(t)
	next, s, gen, err := PrepareStagingDNSPlan(key, id, image, 8)
	if err != nil || gen != 9 || !s.Prepared || len(s.Records) != 2 || s.Records[0].Name != s.Records[1].Name || s.Records[0].State != "new" {
		t.Fatal("legitimate exact CA plan refused")
	}
	return key, id, next
}
func TestDNSPlanExactSourceEncryptionUncertainIntentAndPersistentWait(t *testing.T) {
	key, id, image := preparedDNSPlanFixture(t)
	m, _, _ := decode(key, id, image)
	p, err := openDNSPlan(key, id, m)
	if err != nil || p.Records[0].Value == p.Records[1].Value || p.Records[0].Owner == p.Records[1].Owner {
		t.Fatal("distinct values/ownership collapsed")
	}
	s, _, _ := ReadStagingDNSPlan(key, id, image)
	meta, _ := json.Marshal(s)
	for _, secret := range []string{configToken, configZoneID, orderURLFixture, p.Records[0].Owner, p.Records[0].Value} {
		if bytes.Contains(meta, []byte(secret)) || bytes.Contains(image, []byte(secret)) {
			t.Fatal("internal scope leaked")
		}
	}
	if next, _, _, err := PrepareStagingDNSPlan(key, id, image, 9); err == nil || next != nil {
		t.Fatal("plan ownership reset")
	}
	at := time.Now().UTC()
	next, attempt, s, gen, err := beginStagingDNSAttemptAt(key, id, image, 9, 0, at)
	if err != nil || gen != 10 || attempt == nil || attempt.lease.readOnly || s.Records[0].State != "creating" || s.Records[0].Attempts != 1 {
		t.Fatal("legitimate intent refused")
	}
	if !bytes.Equal(m.CloudflareConfigs[0].Ciphertext, func() []byte { mm, _, _ := decode(key, id, next); return mm.CloudflareConfigs[0].Ciphertext }()) {
		t.Fatal("DNS intent changed token")
	}
	if out, a, _, _, err := beginStagingDNSAttemptAt(key, id, next, 10, 0, at); err == nil || out != nil || a != nil {
		t.Fatal("early retry permitted")
	}
	copyAttempt := *attempt
	wait := at.Add(5 * time.Minute)
	deferred, s, gen, err := DeferStagingDNSAttempt(key, id, next, attempt, providerretry.Hint{NotBefore: wait})
	if err != nil || gen != 11 || s.Records[0].Attempts != 1 || s.Records[0].NotBefore < mustDNSTime(wait.Format("2006-01-02T15:04:05Z")).Format("2006-01-02T15:04:05Z") {
		t.Fatal("longer provider wait lost")
	}
	if out, _, _, err := DeferStagingDNSAttempt(key, id, next, &copyAttempt, providerretry.Hint{}); err == nil || out != nil {
		t.Fatal("copied lease reused")
	}
	// Reopening or restoring bytes cannot recreate first-write authority.
	next, attempt, s, gen, err = beginStagingDNSAttemptAt(key, id, deferred, 11, 0, mustDNSTime(s.Records[0].NotBefore))
	if err != nil || gen != 12 || attempt == nil || !attempt.lease.readOnly || s.Records[0].Attempts != 2 {
		t.Fatal("reopened pending scope granted replay or refused legitimate read")
	}
	next, s, _, err = deferStagingDNSAttemptAt(key, id, next, attempt, providerretry.Hint{Blocked: true}, mustDNSTime(s.Records[0].NotBefore))
	if err != nil || !s.Records[0].Blocked || s.Records[0].Attempts != 2 {
		t.Fatal("malformed hint reset intent")
	}
	if out, a, _, _, err := beginStagingDNSAttemptAt(key, id, next, 13, 0, at.Add(30*time.Minute)); err == nil || out != nil || a != nil {
		t.Fatal("blocked policy reopened")
	}
}
func TestDNSPlanWrongScopeStaleMalformedAndContextRefuseBeforeOutput(t *testing.T) {
	key, id, image := preparedDNSPlanFixture(t)
	if next, a, s, gen, err := BeginStagingDNSAttempt(key, id, image, 8, 0); !errors.Is(err, ErrStaleGeneration) || next != nil || a != nil || s.Prepared || gen != 0 {
		t.Fatal("stale DNS scope accepted")
	}
	for _, index := range []int{-1, 2, 1000000} {
		if next, a, _, _, err := BeginStagingDNSAttempt(key, id, image, 9, index); err == nil || next != nil || a != nil {
			t.Fatal("foreign index accepted")
		}
	}
	for _, change := range []func(*dnsPlanPayload){
		func(p *dnsPlanPayload) { p.Order = orderURLFixture + "1" }, func(p *dnsPlanPayload) { p.Account = "bad" }, func(p *dnsPlanPayload) { p.ZoneID = "../path" }, func(p *dnsPlanPayload) { p.ZoneName = "other.com" },
		func(p *dnsPlanPayload) { p.ConfigGeneration++ }, func(p *dnsPlanPayload) { p.PreparedAt = "2026-02-30T00:00:00Z" }, func(p *dnsPlanPayload) { p.PreparedGeneration = 1 },
		func(p *dnsPlanPayload) { p.Records[0].Name = "_acme-challenge.foreign.com" }, func(p *dnsPlanPayload) { p.Records[0].Domain = "foreign.com" }, func(p *dnsPlanPayload) { p.Records[0].Value = p.Records[1].Value },
		func(p *dnsPlanPayload) { p.Records[0].Owner = p.Records[1].Owner }, func(p *dnsPlanPayload) { p.Records[0].State = "created" }, func(p *dnsPlanPayload) { p.Records = p.Records[:1] }, func(p *dnsPlanPayload) { p.Records[0].Blocked = true },
		func(p *dnsPlanPayload) { p.Records[0], p.Records[1] = p.Records[1], p.Records[0] },
		func(p *dnsPlanPayload) {
			p.Records[0].Value = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
		},
	} {
		m, _, _ := decode(key, id, image)
		p, _ := openDNSPlan(key, id, m)
		change(&p)
		plain, _ := json.Marshal(p)
		k, _ := dnsPlanKey(key, id)
		item := m.DNSPlans[0]
		item.Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, item), plain)
		clear(k)
		clear(plain)
		m.DNSPlans = []sealedRecord{item}
		bad, _ := encode(key, m)
		if records, gen, err := Open(key, id, bad); err == nil || records != nil || gen != 0 {
			t.Fatal("malformed job released metadata")
		}
	}
	for _, change := range []func(*manifest){func(m *manifest) { m.DNSPlans = append(m.DNSPlans, m.DNSPlans[0]) }, func(m *manifest) { m.DNSPlans[0].ID[0] ^= 1 }, func(m *manifest) { m.DNSPlans[0].Generation = 1 }, func(m *manifest) { m.DNSPlans[0].Ciphertext[30] ^= 1 }, func(m *manifest) { m.DNSPlans[0].Ciphertext = make([]byte, 8193) }, func(m *manifest) { m.CloudflareConfigs = nil }, func(m *manifest) { m.ACMEOrders = nil }} {
		m, _, _ := decode(key, id, image)
		change(&m)
		bad, _ := encode(key, m)
		if records, _, err := Open(key, id, bad); err == nil || records != nil {
			t.Fatal("tampered/context-swapped plan released metadata")
		}
	}
	// An authenticated outer MAC does not make wrong-purpose ciphertext valid.
	m, _, _ := decode(key, id, image)
	p, _ := openDNSPlan(key, id, m)
	plain, _ := json.Marshal(p)
	m.DNSPlans[0].Ciphertext, _ = inventoryseal.Seal(key, attachmentContext(id, m.DNSPlans[0]), plain)
	bad, _ := encode(key, m)
	if _, _, err := ReadStagingDNSPlan(key, id, bad); err == nil {
		t.Fatal("wrong purpose opened")
	}
	key, id, image = dnsPlanFixture(t)
	m, _, _ = decode(key, id, image)
	config, _ := openCloudflareConfig(key, id, m)
	config.ZoneName = "other.com"
	k, _ := cloudflareConfigKey(key, id)
	plain, _ = json.Marshal(config)
	m.CloudflareConfigs[0].Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, m.CloudflareConfigs[0]), plain)
	clear(k)
	clear(config.Token)
	clear(plain)
	bad, _ = encode(key, m)
	if next, _, _, err := PrepareStagingDNSPlan(key, id, bad, 8); err == nil || next != nil {
		t.Fatal("wrong zone planned")
	}
}
func TestDNSPlanLeaseExactImageNoReplayAndBudgetExhaustion(t *testing.T) {
	key, id, image := preparedDNSPlanFixture(t)
	now := time.Now().UTC()
	for n := 1; n <= providerretry.MaxAttempts; n++ {
		_, gen, _ := Open(key, id, image)
		next, a, s, _, err := beginStagingDNSAttemptAt(key, id, image, gen, 0, now)
		if err != nil || a == nil || a.lease.readOnly != (n > 1) || s.Records[0].Attempts != n {
			t.Fatal("bounded intended attempt failed")
		}
		image = next
		now = mustDNSTime(s.Records[0].NotBefore)
	}
	_, gen, _ := Open(key, id, image)
	if next, a, _, _, err := beginStagingDNSAttemptAt(key, id, image, gen, 0, now); err == nil || next != nil || a != nil {
		t.Fatal("budget exhaustion bypassed")
	}
	key, id, image = preparedDNSPlanFixture(t)
	next, a, _, _, err := BeginStagingDNSAttempt(key, id, image, 9, 0)
	if err != nil {
		t.Fatal(err)
	}
	changed, _, err := Append(key, id, next, demo(t, "rootwell-demo-certificate.pem"), "team", "service")
	if err != nil {
		t.Fatal(err)
	}
	if out, _, _, err := DeferStagingDNSAttempt(key, id, changed, a, providerretry.Hint{}); !errors.Is(err, ErrStaleGeneration) || out != nil {
		t.Fatal("changed image reused lease")
	}
	if out, _, _, err := DeferStagingDNSAttempt(key, id, next, a, providerretry.Hint{}); err == nil || out != nil {
		t.Fatal("failed lease validation left reusable capability")
	}
	if out, _, _, err := DeferStagingDNSAttempt(key, id, next, &DNSAttempt{}, providerretry.Hint{}); err == nil || out != nil {
		t.Fatal("empty serialized lease granted authority")
	}
}
func TestDNSPlanClosureArchiveAndCleanupCapacity(t *testing.T) {
	key, id, image := preparedDNSPlanFixture(t)
	m, _, _ := decode(key, id, image)
	p, _ := openDNSPlan(key, id, m)
	closed, _, gen, err := closeStagingRequestAt(key, id, image, 9, mustDNSTime(p.Expires).Add(time.Second))
	if err != nil || gen != 10 {
		t.Fatal("unused plan closure failed")
	}
	rotated, _, _, err := ChangeCloudflareConfig(key, id, closed, 10, configZoneID, "example.com", []byte(bytes.Repeat([]byte{'B'}, 40)), false)
	if err != nil {
		t.Fatal("closed harmless plan blocked rotation")
	}
	cm, _, err := decode(key, id, rotated)
	if err != nil || len(cm.DNSPlans) != 0 {
		t.Fatal("archive reopened plan")
	}
	archive, scope, _, err := openClosedRequest(key, id, cm, cm.ClosedRequests[0])
	if err != nil || len(archive.DNSPlans) != 1 {
		t.Fatal("archived plan lost")
	}
	historical, err := openDNSPlan(key, id, scope)
	if err != nil || !reflect.DeepEqual(p, historical) {
		t.Fatal("archived intent changed")
	}
	started, _, _, _, err := BeginStagingDNSAttempt(key, id, image, 9, 0)
	if err != nil {
		t.Fatal(err)
	}
	eligibility, _, err := ReadNewStagingRequest(key, id, started)
	if err != nil || eligibility.Available || eligibility.Reason != "dns-cleanup-needed" {
		t.Fatal("uncertain DNS ownership missing from closure status")
	}
	if out, _, _, err := closeStagingRequestAt(key, id, started, 10, mustDNSTime(p.Expires).Add(time.Second)); err == nil || out != nil {
		t.Fatal("expired request abandoned uncertain DNS ownership")
	}
	m, _, _ = decode(key, id, started)
	m.Generation = maxGeneration - 24
	m.History = nil
	near, _ := encode(key, m)
	if out, _, err := Append(key, id, near, demo(t, "rootwell-demo-certificate.pem"), "team", "service"); !errors.Is(err, ErrLimit) || out != nil {
		t.Fatal("ordinary write consumed cleanup generations")
	}
	if _, _, err := Open(key, id, near); err != nil {
		t.Fatal("reserved image cannot reopen")
	}
}

func TestDNSPlanReservationsAddToPendingIssuanceAndPreserveMaterial(t *testing.T) {
	key, id, image := preparedDNSPlanFixture(t)
	var err error
	image, _, _, _, err = BeginStagingDNSAttempt(key, id, image, 9, 0)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = UpdateStagingOrder(key, id, image, 10, "", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = BeginStagingValidation(key, id, image, 11, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = FinishStagingValidation(key, id, image, 12, validationFixture())
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, err = PrepareStagingCertificateRequest(key, id, image, 13)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, _, err = BeginStagingIssuance(key, id, image, 14, false)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := openDNSPlan(key, id, m)
	reserve, err := dnsTotalReserve(key, id, m, p)
	if err != nil || reserve != 25 || reservedImageBytes(key, id, m) != issuanceByteReserve+dnsPlanByteReserve+24*dnsTransitionByteReserve {
		t.Fatal("issuance and cleanup reservations overlap")
	}
	m.History = nil
	m.Generation = maxGeneration - 25
	near, _ := encode(key, m)
	if out, _, err := Append(key, id, near, demo(t, "rootwell-demo-certificate.pem"), "team", "service"); !errors.Is(err, ErrLimit) || out != nil {
		t.Fatal("generic write consumed overlapping reservation")
	}
	if _, _, err := Open(key, id, near); err != nil {
		t.Fatal("valid combined reserve could not reopen")
	}
	// Library material is unrelated to the new protocol planning layer.
	key, id, image = preparedDNSPlanFixture(t)
	cert, private, fp := generatedPair(t)
	defer clear(private)
	image, _, _, err = AppendMaterial(key, id, image, cert, private, nil, "team", "service", fp, false, 9)
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ = decode(key, id, image)
	original := bytes.Clone(m.Materials[0].Ciphertext)
	image, _, _, _, err = BeginStagingDNSAttempt(key, id, image, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ = decode(key, id, image)
	if !bytes.Equal(original, m.Materials[0].Ciphertext) {
		t.Fatal("DNS intent altered certificate private material")
	}
}

func TestDNSPlanClockAndUnrequiredRecordsHaveNoAuthority(t *testing.T) {
	key, id, image := dnsPlanFixture(t)
	m, _, _ := decode(key, id, image)
	order, _ := openOrder(key, id, m)
	for _, at := range []time.Time{mustDNSTime(order.Started).Add(-time.Second), mustDNSTime(order.Expires), time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if next, _, _, err := prepareStagingDNSPlanAt(key, id, image, 8, at); err == nil || next != nil {
			t.Fatal("invalid clock allowed plan")
		}
	}
	// A CA-already-valid domain is not a fabricated DNS request.
	info := orderInstructionsFixture()
	info.Records[0] = acmeorder.TXT{Domain: "*.example.com", Name: "_acme-challenge.example.com", Required: false}
	image, _, _, err := UpdateStagingOrder(key, id, image, 8, "", &info, false)
	if err != nil {
		t.Fatal(err)
	}
	image, s, _, err := PrepareStagingDNSPlan(key, id, image, 9)
	if err != nil || len(s.Records) != 1 || s.Records[0].Domain != "example.com" {
		t.Fatal("already-valid domain got a DNS job")
	}
	if next, a, _, _, err := beginStagingDNSAttemptAt(key, id, image, 10, 0, mustDNSTime(s.Expires)); err == nil || next != nil || a != nil {
		t.Fatal("expired scope allowed attempt")
	}
}

func TestDNSPlanCrossInstallationAndLegacySchemaRefuse(t *testing.T) {
	key, id, image := preparedDNSPlanFixture(t)
	otherKey, otherID := testIdentity(t)
	if s, gen, err := ReadStagingDNSPlan(otherKey, otherID, image); err == nil || s.Prepared || gen != 0 {
		t.Fatal("cross-installation plan opened")
	}
	m, _, _ := decode(key, id, image)
	m.InstallationID = otherID
	swapped, _ := encode(key, m)
	if _, _, err := Open(key, otherID, swapped); err == nil {
		t.Fatal("valid outer MAC allowed wrong installation context")
	}
	var outer envelope
	if !strictJSON(image, &outer) {
		t.Fatal("invalid fixture")
	}
	var old struct {
		Version           int            `json:"version"`
		InstallationID    []byte         `json:"installation_id"`
		Generation        uint64         `json:"generation"`
		Records           []sealedRecord `json:"records"`
		History           []sealedRecord `json:"history,omitempty"`
		ACMEAccounts      []sealedRecord `json:"acme_accounts,omitempty"`
		ACMEOrders        []sealedRecord `json:"acme_orders,omitempty"`
		CloudflareConfigs []sealedRecord `json:"cloudflare_configs,omitempty"`
	}
	if strictJSON(outer.Body, &old) {
		t.Fatal("prior schema silently dropped DNS ownership")
	}
}
func FuzzDNSPlanPayload(f *testing.F) {
	key, id, image := preparedDNSPlanFixture(f)
	var records []dnsPlanRecord
	for i, r := range orderInstructionsFixture().Records {
		records = append(records, dnsPlanRecord{Domain: r.Domain, Name: r.Name, Value: r.Value, Owner: strings.Repeat(fmt.Sprint(i+1), 32), State: "new"})
	}
	seed, _ := json.Marshal(records)
	f.Add(seed)
	m, _, _ := decode(key, id, image)
	prepared, _ := openDNSPlan(key, id, m)
	at := mustDNSTime(prepared.PreparedAt)
	retry := providerretry.State{Attempts: 1, LastAt: prepared.PreparedAt, NotBefore: at.Add(time.Minute).Format("2006-01-02T15:04:05Z")}
	for _, state := range []string{"creating", "borrowed", "created", "deleting", "deleted"} {
		rows := append([]dnsPlanRecord(nil), records...)
		r := &rows[0]
		r.State = state
		r.Retry = retry
		r.OutcomeAt = prepared.PreparedAt
		if state != "creating" {
			r.CheckedAt = prepared.PreparedAt
		}
		if state == "created" || state == "deleting" || state == "deleted" {
			r.ID = strings.Repeat("c", 32)
		}
		if state == "deleting" || state == "deleted" {
			r.Cleanup = &retry
		}
		seed, _ := json.Marshal(rows)
		f.Add(seed)
	}
	f.Add([]byte("null"))
	for _, cleanup := range []bool{false, true} {
		rows := append([]dnsPlanRecord(nil), records...)
		r := &rows[0]
		r.State = "creating"
		r.Retry = retry
		r.Retry.Attempts = 6
		r.OutcomeAt = at.Add(2 * time.Minute).Format("2006-01-02T15:04:05Z")
		recovery := &dnsRecoveryState{Retry: providerretry.State{Attempts: 1, LastAt: at.Add(time.Minute).Format("2006-01-02T15:04:05Z"), NotBefore: at.Add(2 * time.Minute).Format("2006-01-02T15:04:05Z")}}
		if cleanup {
			r.State = "deleting"
			r.ID = strings.Repeat("c", 32)
			r.CheckedAt = prepared.PreparedAt
			prior := r.Retry
			r.Cleanup = &prior
			r.CleanupRecovery = recovery
		} else {
			r.Recovery = recovery
		}
		seed, _ := json.Marshal(rows)
		f.Add(seed)
	}
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		m, _, _ := decode(key, id, image)
		p, _ := openDNSPlan(key, id, m)
		plain := data
		if strictJSON(data, &p.Records) {
			plain, _ = json.Marshal(p)
			defer clear(plain)
		}
		k, _ := dnsPlanKey(key, id)
		item := m.DNSPlans[0]
		item.Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, item), plain)
		clear(k)
		m.DNSPlans = []sealedRecord{item}
		candidate, _ := encode(key, m)
		s, gen, err := ReadStagingDNSPlan(key, id, candidate)
		if err != nil && (s.Prepared || gen != 0 || s.Records != nil) {
			t.Fatal("partial result")
		}
	})
}
