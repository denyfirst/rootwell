package inventorystore

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"sync/atomic"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

const dnsPlanByteReserve = 64 << 10

func reservedImageBytes(key, id []byte, m manifest) int {
	reserve := 0
	if len(m.DNSPlans) > 0 {
		reserve += dnsPlanByteReserve
	}
	if pendingIssuance(key, id, m) {
		reserve += issuanceByteReserve
	}
	return reserve
}

// DNSPlanStatus is local planning evidence, not DNS existence/CA verification.
// No token, provider ID, owner marker, TXT value or internal URL is public here.
type DNSPlanStatus struct {
	Prepared   bool                  `json:"prepared"`
	PreparedAt string                `json:"prepared_at"`
	Expires    string                `json:"expires"`
	Records    []DNSPlanRecordStatus `json:"records"`
}
type DNSPlanRecordStatus struct {
	Domain    string `json:"domain"`
	Name      string `json:"name"`
	State     string `json:"state"`
	Attempts  int    `json:"attempts"`
	NotBefore string `json:"not_before"`
	Blocked   bool   `json:"blocked"`
}
type dnsPlanRecord struct {
	Domain  string              `json:"domain"`
	Name    string              `json:"name"`
	Value   string              `json:"value"`
	Owner   string              `json:"owner"`
	State   string              `json:"state"`
	Retry   providerretry.State `json:"retry"`
	Blocked bool                `json:"blocked"`
}
type dnsPlanPayload struct {
	Order              string          `json:"order"`
	Account            string          `json:"account"`
	ZoneID             string          `json:"zone_id"`
	ZoneName           string          `json:"zone_name"`
	ConfigGeneration   uint64          `json:"config_generation"`
	PreparedAt         string          `json:"prepared_at"`
	PreparedGeneration uint64          `json:"prepared_generation"`
	Expires            string          `json:"expires"`
	Records            []dnsPlanRecord `json:"records"`
}

// DNSAttempt is opaque and process-local. No network or secret borrower exists
// in this increment. Copies share the same consumed state for provider waits.
type DNSAttempt struct{ lease *dnsAttemptLease }
type dnsAttemptLease struct {
	imageHash  [32]byte
	generation uint64
	index      int
	readOnly   bool
	used       atomic.Bool
}

func dnsPlanID() []byte { h := sha256.Sum256([]byte("rootwell.acme-dns-plan.v1")); return h[:] }
func dnsPlanKey(key, id []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, id, "rootwell.acme-dns-plan-key.v1", 32)
}
func dnsPlanHex(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func openDNSPlan(key, id []byte, m manifest) (dnsPlanPayload, error) {
	bad := func() (dnsPlanPayload, error) { return dnsPlanPayload{}, ErrInvalid }
	if len(m.DNSPlans) == 0 {
		return dnsPlanPayload{}, nil
	}
	if len(m.DNSPlans) != 1 {
		return bad()
	}
	item := m.DNSPlans[0]
	if !bytes.Equal(item.ID, dnsPlanID()) || item.Generation < 4 || item.Generation > m.Generation || len(item.Ciphertext) == 0 || len(item.Ciphertext) > 8192 {
		return bad()
	}
	k, err := dnsPlanKey(key, id)
	if err != nil {
		return bad()
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	defer clear(plain)
	if err != nil {
		return bad()
	}
	var p dnsPlanPayload
	if !strictJSON(plain, &p) || !acmeorder.Time(p.PreparedAt) || !acmeorder.Time(p.Expires) || p.Expires <= p.PreparedAt || p.PreparedGeneration < 4 || p.PreparedGeneration > item.Generation || p.ConfigGeneration < 2 || p.ConfigGeneration >= p.PreparedGeneration || len(p.Records) < 1 || len(p.Records) > 8 || !dnsPlanHex(p.ZoneID) {
		return bad()
	}
	if mustDNSTime(p.PreparedAt).Year() > 2100 {
		return bad()
	}
	names, ok := acmeorder.Names([]string{p.ZoneName})
	if !ok || names[0] != p.ZoneName || strings.HasPrefix(p.ZoneName, "*.") {
		return bad()
	}
	order, err := openOrder(key, id, m)
	if err != nil || order.URL == "" || p.Order != order.URL || p.Account != order.Fingerprint || order.Expires == "" || p.Expires < order.Expires || p.PreparedAt < order.Started {
		return bad()
	}
	// Active configuration must still be the exact one selected for this order.
	// Closed unattempted plans have no authority and survive token rotation/removal.
	if !m.historical {
		config, err := openCloudflareConfig(key, id, m)
		defer clear(config.Token)
		if err != nil || len(m.CloudflareConfigs) != 1 || p.ConfigGeneration != m.CloudflareConfigs[0].Generation || p.ZoneID != config.ZoneID || p.ZoneName != config.ZoneName || p.PreparedAt < config.SavedAt {
			return bad()
		}
	}
	seenDomains, seenOwners, seenTuples := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, r := range p.Records {
		if i > 0 && p.Records[i-1].Domain >= r.Domain || seenDomains[r.Domain] || seenOwners[r.Owner] || seenTuples[r.Name+"\x00"+r.Value] || !dnsPlanHex(r.Owner) || r.Owner == strings.Repeat("0", 32) || !providerretry.Valid(r.Retry) {
			return bad()
		}
		seenDomains[r.Domain], seenOwners[r.Owner], seenTuples[r.Name+"\x00"+r.Value] = true, true, true
		base := strings.TrimPrefix(r.Domain, "*.")
		if r.Name != "_acme-challenge."+base || base != p.ZoneName && !strings.HasSuffix(base, "."+p.ZoneName) {
			return bad()
		}
		found := false
		for _, source := range order.Records {
			if source.Domain == r.Domain && source.Name == r.Name {
				found = true
				if source.Required && source.Value != r.Value {
					return bad()
				}
			}
		}
		decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(r.Value)
		if !found || decodeErr != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != r.Value {
			return bad()
		}
		if r.State == "new" {
			if r.Retry.Attempts != 0 || r.Blocked {
				return bad()
			}
		} else if r.State != "creating" || r.Retry.Attempts < 1 || r.Retry.LastAt < p.PreparedAt || m.historical {
			return bad()
		}
	}
	for _, source := range order.Records {
		if source.Required && !seenDomains[source.Domain] {
			return bad()
		}
	}
	return p, nil
}

func dnsPlanReserve(p dnsPlanPayload) int {
	reserve := 0
	for _, r := range p.Records {
		if r.State == "creating" {
			reserve += 3
		}
	}
	return reserve
}
func dnsTotalReserve(key, id []byte, m manifest, p dnsPlanPayload) (int, error) {
	reserve := dnsPlanReserve(p)
	if reserve == 0 {
		return 0, nil
	}
	order, err := openOrder(key, id, m)
	if err != nil {
		return 0, err
	}
	s, err := accountStatus(key, id, m)
	if err != nil {
		return 0, err
	}
	if s.Registration == "registration-pending" {
		reserve++
	}
	if order.State == "request-pending" {
		reserve += 2
	}
	if order.State == "order-known" || order.State == "validation-pending" {
		reserve++
	}
	if pendingIssuance(key, id, m) {
		reserve++
	}
	return reserve, nil
}
func publicDNSPlan(p dnsPlanPayload, deadline string) DNSPlanStatus {
	s := DNSPlanStatus{Records: []DNSPlanRecordStatus{}}
	if p.PreparedAt == "" {
		return s
	}
	s.Prepared = true
	s.PreparedAt = p.PreparedAt
	s.Expires = min(p.Expires, deadline)
	for _, r := range p.Records {
		s.Records = append(s.Records, DNSPlanRecordStatus{Domain: r.Domain, Name: r.Name, State: r.State, Attempts: r.Retry.Attempts, NotBefore: r.Retry.NotBefore, Blocked: r.Blocked})
	}
	return s
}
func ReadStagingDNSPlan(key, id, image []byte) (DNSPlanStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return DNSPlanStatus{}, 0, err
	}
	p, err := openDNSPlan(key, id, m)
	if err != nil {
		return DNSPlanStatus{}, 0, err
	}
	order, err := openOrder(key, id, m)
	if err != nil {
		return DNSPlanStatus{}, 0, err
	}
	return publicDNSPlan(p, order.Expires), m.Generation, nil
}
func sealDNSPlan(key, id []byte, m manifest, p dnsPlanPayload, action string) ([]byte, DNSPlanStatus, uint64, error) {
	if m.Generation >= maxGeneration || len(m.History) >= maxHistory {
		return nil, DNSPlanStatus{}, 0, ErrLimit
	}
	k, err := dnsPlanKey(key, id)
	if err != nil {
		return nil, DNSPlanStatus{}, 0, ErrInvalid
	}
	defer clear(k)
	plain, err := json.Marshal(p)
	defer clear(plain)
	if err != nil || len(plain) > 8192-64 {
		return nil, DNSPlanStatus{}, 0, ErrInvalid
	}
	m.Generation++
	item := sealedRecord{ID: dnsPlanID(), Generation: m.Generation}
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
	if err != nil {
		return nil, DNSPlanStatus{}, 0, ErrInvalid
	}
	m.DNSPlans = []sealedRecord{item}
	if err := addEvent(key, &m, action, []string{p.Account}); err != nil {
		return nil, DNSPlanStatus{}, 0, err
	}
	next, err := encode(key, m)
	if err != nil {
		return nil, DNSPlanStatus{}, 0, err
	}
	s, gen, err := ReadStagingDNSPlan(key, id, next)
	if err != nil {
		return nil, DNSPlanStatus{}, 0, err
	}
	return next, s, gen, nil
}
func PrepareStagingDNSPlan(key, id, image []byte, expected uint64) ([]byte, DNSPlanStatus, uint64, error) {
	return prepareStagingDNSPlanAt(key, id, image, expected, time.Now().UTC())
}
func prepareStagingDNSPlanAt(key, id, image []byte, expected uint64, at time.Time) ([]byte, DNSPlanStatus, uint64, error) {
	bad := func(err error) ([]byte, DNSPlanStatus, uint64, error) { return nil, DNSPlanStatus{}, 0, err }
	m, _, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	if expected == 0 || expected != m.Generation {
		return bad(ErrStaleGeneration)
	}
	if len(m.DNSPlans) != 0 || m.historical {
		return bad(ErrInvalid)
	}
	order, err := openOrder(key, id, m)
	if err != nil || order.State != "dns-ready" && order.State != "dns-acknowledged" {
		return bad(ErrInvalid)
	}
	config, err := openCloudflareConfig(key, id, m)
	defer clear(config.Token)
	if err != nil || len(m.CloudflareConfigs) != 1 {
		return bad(ErrInvalid)
	}
	now := at.UTC().Format("2006-01-02T15:04:05Z")
	if at.Year() < 2020 || at.Year() > 2100 || now < order.Started || now < config.SavedAt || now >= order.Expires {
		return bad(ErrInvalid)
	}
	p := dnsPlanPayload{Order: order.URL, Account: order.Fingerprint, ZoneID: config.ZoneID, ZoneName: config.ZoneName, ConfigGeneration: m.CloudflareConfigs[0].Generation, PreparedAt: now, PreparedGeneration: m.Generation + 1, Expires: order.Expires, Records: []dnsPlanRecord{}}
	for _, r := range order.Records {
		if !r.Required {
			continue
		}
		base := strings.TrimPrefix(r.Domain, "*.")
		if base != config.ZoneName && !strings.HasSuffix(base, "."+config.ZoneName) {
			return bad(ErrInvalid)
		}
		marker := make([]byte, 16)
		if _, err := rand.Read(marker); err != nil {
			return bad(ErrInvalid)
		}
		p.Records = append(p.Records, dnsPlanRecord{Domain: r.Domain, Name: r.Name, Value: r.Value, Owner: hex.EncodeToString(marker), State: "new"})
	}
	if len(p.Records) == 0 || len(image) > maxImage-dnsPlanByteReserve {
		return bad(ErrInvalid)
	}
	return sealDNSPlan(key, id, m, p, "acme-dns-plan-prepared")
}

// Begin returns an image that MUST durably commit before a future connector can
// receive its lease. The first intent marks creating even if no bytes were sent;
// reopened/uncertain scope can mint read-only attempts only, never reset/replay.
func BeginStagingDNSAttempt(key, id, image []byte, expected uint64, index int) ([]byte, *DNSAttempt, DNSPlanStatus, uint64, error) {
	return beginStagingDNSAttemptAt(key, id, image, expected, index, time.Now().UTC())
}
func beginStagingDNSAttemptAt(key, id, image []byte, expected uint64, index int, at time.Time) ([]byte, *DNSAttempt, DNSPlanStatus, uint64, error) {
	bad := func(err error) ([]byte, *DNSAttempt, DNSPlanStatus, uint64, error) {
		return nil, nil, DNSPlanStatus{}, 0, err
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	if expected == 0 || expected != m.Generation {
		return bad(ErrStaleGeneration)
	}
	p, err := openDNSPlan(key, id, m)
	if err != nil || m.historical || index < 0 || index >= len(p.Records) {
		return bad(ErrInvalid)
	}
	order, err := openOrder(key, id, m)
	if err != nil {
		return bad(err)
	}
	if at.Year() < 2020 || at.Year() > 2100 || at.UTC().Format("2006-01-02T15:04:05Z") < p.PreparedAt || !at.Before(mustDNSTime(min(p.Expires, order.Expires))) || p.Records[index].Blocked {
		return bad(ErrInvalid)
	}
	readOnly := p.Records[index].State == "creating"
	jitter, err := rand.Int(rand.Reader, big.NewInt(31))
	if err != nil {
		return bad(ErrInvalid)
	}
	retry, err := providerretry.Begin(p.Records[index].Retry, at, int(jitter.Int64()))
	if err != nil {
		return bad(err)
	}
	p.Records[index].State = "creating"
	p.Records[index].Retry = retry
	reserve, err := dnsTotalReserve(key, id, m, p)
	if err != nil {
		return bad(err)
	}
	if reserve < 0 || reserve > 28 {
		return bad(ErrInvalid)
	}
	if m.Generation > maxGeneration-uint64(reserve)-2 || len(m.History) > maxHistory-reserve-2 || len(image) > maxImage-dnsPlanByteReserve {
		return bad(ErrLimit)
	}
	next, s, gen, err := sealDNSPlan(key, id, m, p, "acme-dns-attempt-started")
	if err != nil {
		return bad(err)
	}
	return next, &DNSAttempt{lease: &dnsAttemptLease{imageHash: sha256.Sum256(next), generation: gen, index: index, readOnly: readOnly}}, s, gen, nil
}
func mustDNSTime(s string) time.Time { t, _ := time.Parse("2006-01-02T15:04:05Z", s); return t }

// Defer carries only a bounded provider hint into the same pending intent.
// It cannot mark a record created/deleted or disclose/borrow credentials.
// Invalid/too-long hints permanently block this policy, retaining prior state.
func DeferStagingDNSAttempt(key, id, image []byte, attempt *DNSAttempt, hint providerretry.Hint) ([]byte, DNSPlanStatus, uint64, error) {
	if attempt == nil || attempt.lease == nil || !attempt.lease.used.CompareAndSwap(false, true) {
		return nil, DNSPlanStatus{}, 0, ErrInvalid
	}
	lease := attempt.lease
	if lease.imageHash != sha256.Sum256(image) {
		return nil, DNSPlanStatus{}, 0, ErrStaleGeneration
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, DNSPlanStatus{}, 0, err
	}
	if m.Generation != lease.generation || m.historical {
		return nil, DNSPlanStatus{}, 0, ErrStaleGeneration
	}
	p, err := openDNSPlan(key, id, m)
	if err != nil || lease.index < 0 || lease.index >= len(p.Records) {
		return nil, DNSPlanStatus{}, 0, ErrInvalid
	}
	r := &p.Records[lease.index]
	if lease.readOnly != (r.Retry.Attempts > 1) {
		return nil, DNSPlanStatus{}, 0, ErrInvalid
	}
	next, err := providerretry.Apply(r.Retry, hint)
	if err != nil {
		r.Blocked = true
	} else {
		r.Retry = next
	}
	return sealDNSPlan(key, id, m, p, "acme-dns-wait-saved")
}
