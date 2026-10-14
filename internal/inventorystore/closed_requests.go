package inventorystore

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

const maxClosedRequests = 32
const maxClosedRequestBytes = 64 << 10

type NewRequestStatus struct {
	Available   bool   `json:"available"`
	Reason      string `json:"reason"`
	ClosedCount int    `json:"closed_count"`
}

// Only nested encrypted fields, never plaintext keys/CSR/provider errors.
type closedRequest struct {
	ClosedAt         string         `json:"closed_at"`
	ClosedGeneration uint64         `json:"closed_generation"`
	Reason           string         `json:"reason"`
	Orders           []sealedRecord `json:"orders"`
	Requests         []sealedRecord `json:"requests,omitempty"`
	Issuances        []sealedRecord `json:"issuances,omitempty"`
	DNSPlans         []sealedRecord `json:"dns_plans,omitempty"`
}

func closedRequestKey(key, id []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, id, "rootwell.acme-closed-request-key.v1", 32)
}
func closedRequestID(order string) []byte {
	sum := sha256.Sum256([]byte("rootwell.acme-closed-request.v1:" + order))
	return sum[:]
}
func closedScope(m manifest, p closedRequest) manifest {
	m.ACMEOrders, m.ACMECertificateRequests, m.ACMEIssuances = p.Orders, p.Requests, p.Issuances
	m.DNSPlans = p.DNSPlans
	m.ClosedRequests = nil
	m.historical = true
	return m
}

func closeEligibility(key, id []byte, m manifest, at string) (string, error) {
	if !m.historical {
		dns, err := openDNSPlan(key, id, m)
		if err != nil {
			return "", err
		}
		if dnsPlanReserve(dns) > 0 {
			return "dns-cleanup-needed", nil
		}
	}
	order, err := openOrder(key, id, m)
	if err != nil {
		return "", err
	}
	if !acmeorder.Time(at) || at < order.Started {
		return "clock-unavailable", nil
	}
	if order.State == "not-started" {
		return "not-started", nil
	}
	if order.URL == "" || order.Expires == "" {
		return "unknown-order", nil
	}
	p, err := openIssuance(key, id, m)
	if err != nil {
		return "", err
	}
	if at < p.StartedAt || at < p.CheckedAt || (order.CheckedAt != "" && at < order.CheckedAt) {
		return "clock-unavailable", nil
	}
	if p.Completion != nil {
		if at < p.Completion.SavedAt || at < p.Completion.DeletedAt {
			return "clock-unavailable", nil
		}
		return "complete", nil
	}
	deadline := order.Expires
	if p.Expires != "" {
		deadline = min(deadline, p.Expires)
	}
	if deadline <= at {
		return "expired", nil
	}
	return "active", nil
}

func openClosedRequest(key, id []byte, m manifest, item sealedRecord) (closedRequest, manifest, issuancePayload, error) {
	bad := func() (closedRequest, manifest, issuancePayload, error) {
		return closedRequest{}, manifest{}, issuancePayload{}, ErrInvalid
	}
	if len(item.ID) != 32 || item.Generation < 4 || item.Generation > m.Generation || len(item.Ciphertext) == 0 || len(item.Ciphertext) > maxClosedRequestBytes {
		return bad()
	}
	k, err := closedRequestKey(key, id)
	if err != nil {
		return bad()
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	defer clear(plain)
	var p closedRequest
	if err != nil || !strictJSON(plain, &p) || !acmeorder.Time(p.ClosedAt) || p.ClosedGeneration < 4 || p.ClosedGeneration > item.Generation || len(p.Orders) != 1 || len(p.Requests) > 1 || len(p.Issuances) > 1 || len(p.DNSPlans) > 1 {
		return bad()
	}
	for _, items := range [][]sealedRecord{p.Orders, p.Requests, p.DNSPlans} {
		for _, nested := range items {
			if nested.Generation >= p.ClosedGeneration {
				return bad()
			}
		}
	}
	for _, nested := range p.Issuances {
		if nested.Generation >= p.ClosedGeneration && !(p.Reason == "complete" && nested.Generation == item.Generation && item.Generation > p.ClosedGeneration) {
			return bad()
		}
	}
	scope := closedScope(m, p)
	if _, err := openDNSPlan(key, id, scope); err != nil {
		return bad()
	}
	order, err := openOrder(key, id, scope)
	if err != nil || !bytes.Equal(item.ID, closedRequestID(order.URL)) {
		return bad()
	}
	if _, err := certificateRequestStatus(key, id, scope); err != nil {
		return bad()
	}
	issuance, err := openIssuance(key, id, scope)
	if err != nil {
		return bad()
	}
	if len(p.Issuances) == 1 && p.Issuances[0].Generation >= p.ClosedGeneration && (issuance.Completion == nil || issuance.Completion.DeletedAt == "" || issuance.Completion.DeletedAt < p.ClosedAt) {
		return bad()
	}
	if p.Reason == "complete" {
		// Later pair deletion may occur after closure. Validate original completion
		// at closure, while full linkage uses its current authenticated tombstone.
		if issuance.Completion == nil || p.ClosedAt < issuance.Completion.SavedAt {
			return bad()
		}
		if p.Issuances[0].Generation < p.ClosedGeneration && issuance.Completion.DeletedAt > p.ClosedAt {
			return bad()
		}
	} else {
		reason, err := closeEligibility(key, id, scope, p.ClosedAt)
		if err != nil || reason != "expired" || p.Reason != "expired" {
			return bad()
		}
	}
	return p, scope, issuance, nil
}

func authenticateClosedRequests(key, id []byte, m manifest, records []publicinventory.Record) error {
	if len(m.ClosedRequests) > maxClosedRequests {
		return ErrInvalid
	}
	current, err := openOrder(key, id, m)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	if current.URL != "" {
		seen[current.URL] = true
	}
	lastGen := uint64(0)
	lastAt := ""
	primary := map[string]bool{}
	anchors := map[string]renewalAnchor{}
	active, err := openIssuance(key, id, m)
	if err != nil {
		return err
	}
	if active.Completion != nil {
		primary[active.Completion.Fingerprint] = true
	}
	for _, item := range m.ClosedRequests {
		p, scope, issuance, err := openClosedRequest(key, id, m, item)
		if err != nil {
			return err
		}
		order, err := openOrder(key, id, scope)
		if err != nil || seen[order.URL] || p.ClosedGeneration <= lastGen || p.ClosedAt < lastAt {
			return ErrInvalid
		}
		seen[order.URL], lastGen, lastAt = true, p.ClosedGeneration, p.ClosedAt
		newKey, err := renewalKeyFingerprint(key, id, scope, issuance)
		if err != nil || checkRenewalBinding(order, p.Orders[0].Generation, p.ClosedAt, p.ClosedGeneration, newKey, anchors) != nil {
			return ErrInvalid
		}
		if c := issuance.Completion; c != nil {
			if primary[c.Fingerprint] {
				return ErrInvalid
			}
			primary[c.Fingerprint] = true
			// The nested issuance generation proves deletion ordering; merely
			// resealing the outer archive must not manufacture a later deletion.
			anchors[c.Fingerprint] = renewalAnchor{Names: issuance.Names, Account: issuance.AccountFingerprint, Key: issuance.KeyFingerprint, ClosedAt: p.ClosedAt, ClosedGeneration: p.ClosedGeneration, DeletedAt: c.DeletedAt, DeletedGeneration: p.Issuances[0].Generation}
			if c.DeletedAt == "" {
				for i := range records {
					if records[i].Fingerprint == c.Fingerprint {
						records[i].StagingOrigin = &publicinventory.StagingOrigin{TestOnly: true, Provider: "letsencrypt-staging", VerifiedAt: c.SavedAt, RootFingerprint: c.ChainFingerprints[len(c.ChainFingerprints)-1]}
					}
				}
			}
		}
	}
	if current.State != "not-started" && len(m.ClosedRequests) > 0 && (m.ACMEOrders[0].Generation <= lastGen || current.Started < lastAt) {
		return ErrInvalid
	}
	if current.RenewalSource != "" {
		newKey, err := renewalKeyFingerprint(key, id, m, active)
		if err != nil || checkRenewalBinding(current, m.ACMEOrders[0].Generation, "", 0, newKey, anchors) != nil {
			return ErrInvalid
		}
	}
	return nil
}

func newRequestStatus(key, id []byte, m manifest, at string) (NewRequestStatus, error) {
	reason, err := closeEligibility(key, id, m, at)
	if err != nil {
		return NewRequestStatus{}, err
	}
	for _, item := range m.ClosedRequests {
		p, _, _, err := openClosedRequest(key, id, m, item)
		if err != nil {
			return NewRequestStatus{}, err
		}
		if at < p.ClosedAt {
			reason = "clock-unavailable"
		}
	}
	available := reason == "complete" || reason == "expired"
	if available && (len(m.ClosedRequests) >= maxClosedRequests || m.Generation >= maxGeneration || len(m.History) >= maxHistory) {
		available = false
		reason = "capacity"
	}
	return NewRequestStatus{Available: available, Reason: reason, ClosedCount: len(m.ClosedRequests)}, nil
}

func ReadNewStagingRequest(key, id, image []byte) (NewRequestStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return NewRequestStatus{}, 0, err
	}
	s, err := newRequestStatus(key, id, m, time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	if err != nil {
		return NewRequestStatus{}, 0, err
	}
	return s, m.Generation, nil
}

func sealClosedRequest(key, id []byte, m *manifest, index int, p closedRequest, order string) error {
	k, err := closedRequestKey(key, id)
	if err != nil {
		return ErrInvalid
	}
	defer clear(k)
	plain, err := json.Marshal(p)
	defer clear(plain)
	if err != nil || len(plain) > maxClosedRequestBytes-64 {
		return ErrLimit
	}
	item := sealedRecord{ID: closedRequestID(order), Generation: m.Generation}
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
	if err != nil {
		return ErrInvalid
	}
	if index < 0 {
		m.ClosedRequests = append(m.ClosedRequests, item)
	} else {
		m.ClosedRequests[index] = item
	}
	return nil
}

func CloseStagingRequest(key, id, image []byte, expected uint64) ([]byte, NewRequestStatus, uint64, error) {
	return closeStagingRequestAt(key, id, image, expected, time.Now().UTC())
}
func closeStagingRequestAt(key, id, image []byte, expected uint64, at time.Time) ([]byte, NewRequestStatus, uint64, error) {
	bad := func(err error) ([]byte, NewRequestStatus, uint64, error) { return nil, NewRequestStatus{}, 0, err }
	m, _, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	if expected == 0 || expected != m.Generation {
		return bad(ErrStaleGeneration)
	}
	now := at.UTC().Format("2006-01-02T15:04:05Z")
	s, err := newRequestStatus(key, id, m, now)
	if err != nil {
		return bad(err)
	}
	if !s.Available {
		return bad(ErrInvalid)
	}
	order, err := openOrder(key, id, m)
	if err != nil {
		return bad(err)
	}
	m.Generation++
	p := closedRequest{ClosedAt: now, ClosedGeneration: m.Generation, Reason: s.Reason, Orders: m.ACMEOrders, Requests: m.ACMECertificateRequests, Issuances: m.ACMEIssuances, DNSPlans: m.DNSPlans}
	if err := sealClosedRequest(key, id, &m, -1, p, order.URL); err != nil {
		return bad(err)
	}
	m.ACMEOrders, m.ACMECertificateRequests, m.ACMEIssuances = nil, nil, nil
	m.DNSPlans = nil
	if err := addEvent(key, &m, "acme-request-closed", []string{order.Fingerprint}); err != nil {
		return bad(err)
	}
	next, err := encode(key, m)
	if err != nil {
		return bad(err)
	}
	status, gen, err := ReadNewStagingRequest(key, id, next)
	if err != nil {
		return bad(err)
	}
	return next, status, gen, nil
}

// Called only after record/material removal, with original image authenticated.
func deleteClosedCompletion(key, id []byte, m *manifest, fp string) error {
	for i, item := range m.ClosedRequests {
		k, err := closedRequestKey(key, id)
		if err != nil {
			return ErrInvalid
		}
		plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
		clear(k)
		var p closedRequest
		ok := err == nil && strictJSON(plain, &p)
		clear(plain)
		if !ok {
			return ErrInvalid
		}
		scope := closedScope(*m, p)
		if err := deleteCompletion(key, id, &scope, fp); err != nil {
			return err
		}
		if len(scope.ACMEIssuances) == 0 || bytes.Equal(scope.ACMEIssuances[0].Ciphertext, p.Issuances[0].Ciphertext) {
			continue
		}
		p.Issuances, p.Requests = scope.ACMEIssuances, scope.ACMECertificateRequests
		order, err := openOrder(key, id, scope)
		if err != nil {
			return err
		}
		if err := sealClosedRequest(key, id, m, i, p, order.URL); err != nil {
			return err
		}
	}
	return nil
}
