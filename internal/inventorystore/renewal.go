package inventorystore

import (
	"errors"
	"slices"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

var ErrRenewalSourceInUse = errors.New("close the renewal request before deleting its original certificate")

// Public selection only; no signer, URI, private key or trust authority.
type RenewalSource struct {
	Fingerprint string   `json:"fingerprint"`
	Domains     []string `json:"domains"`
}

type renewalAnchor struct {
	Names                               []string
	Account, Key, ClosedAt, DeletedAt   string
	ClosedGeneration, DeletedGeneration uint64
}

// Public lineage identities only. Historical scopes and their encrypted keys
// remain inside the validator; a summary consumer receives no replay authority.
func completedRenewalSources(key, id []byte, m manifest) (map[string]bool, error) {
	result := map[string]bool{}
	scopes := []manifest{m}
	for _, item := range allClosedRequests(m) {
		_, scope, _, err := openClosedRequest(key, id, m, item)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	for _, scope := range scopes {
		order, err := openOrder(key, id, scope)
		if err != nil {
			return nil, err
		}
		issued, err := openIssuance(key, id, scope)
		if err != nil {
			return nil, err
		}
		if issued.Completion != nil && order.RenewalSource != "" {
			result[order.RenewalSource] = true
		}
	}
	return result, nil
}

func checkRenewalBinding(order orderPayload, orderGeneration uint64, closedAt string, closedGeneration uint64, newKey string, anchors map[string]renewalAnchor) error {
	if order.RenewalSource == "" {
		return nil
	}
	a, ok := anchors[order.RenewalSource]
	if !ok || a.Account != order.Fingerprint || !slices.Equal(a.Names, order.Domains) || a.ClosedAt > order.Started || a.ClosedGeneration >= orderGeneration || newKey != "" && newKey == a.Key {
		return ErrInvalid
	}
	if a.DeletedAt != "" && (closedAt == "" || a.DeletedAt < closedAt || a.DeletedGeneration <= closedGeneration) {
		return ErrInvalid
	}
	return nil
}

func renewalKeyFingerprint(key, id []byte, m manifest, issuance issuancePayload) (string, error) {
	if issuance.StartedAt != "" {
		return issuance.KeyFingerprint, nil
	}
	s, err := certificateRequestStatus(key, id, m)
	return s.Fingerprint, err
}

func renewalSource(key, id []byte, m manifest, fingerprint string) (RenewalSource, error) {
	if !publicinventory.ValidFingerprint(fingerprint) {
		return RenewalSource{}, ErrInvalid
	}
	current, err := openIssuance(key, id, m)
	if err != nil {
		return RenewalSource{}, err
	}
	if current.Completion != nil && current.Completion.Fingerprint == fingerprint && current.Completion.DeletedAt == "" {
		return RenewalSource{Fingerprint: fingerprint, Domains: slices.Clone(current.Names)}, nil
	}
	for _, item := range allClosedRequests(m) {
		_, _, p, err := openClosedRequest(key, id, m, item)
		if err != nil {
			return RenewalSource{}, err
		}
		if p.Completion != nil && p.Completion.Fingerprint == fingerprint && p.Completion.DeletedAt == "" {
			return RenewalSource{Fingerprint: fingerprint, Domains: slices.Clone(p.Names)}, nil
		}
	}
	return RenewalSource{}, ErrInvalid
}

func ReadStagingRenewalSource(key, id, image []byte, expected uint64, fingerprint string) (RenewalSource, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return RenewalSource{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return RenewalSource{}, 0, ErrStaleGeneration
	}
	s, err := renewalSource(key, id, m, fingerprint)
	if err != nil {
		return RenewalSource{}, 0, err
	}
	return s, m.Generation, nil
}

func BeginStagingRenewal(key, id, image []byte, expected uint64, fingerprint string) ([]byte, OrderStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, OrderStatus{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, OrderStatus{}, 0, ErrStaleGeneration
	}
	s, err := renewalSource(key, id, m, fingerprint)
	if err != nil || len(m.ACMEOrders) != 0 || !acmeorder.CanonicalNames(s.Domains) {
		return nil, OrderStatus{}, 0, ErrInvalid
	}
	if m.Generation > maxGeneration-3 || len(m.History) > maxHistory-3 || len(m.ClosedRequests) >= maxClosedRequests {
		return nil, OrderStatus{}, 0, ErrLimit
	}
	account, err := accountStatus(key, id, m)
	if err != nil || account.Registration != "registered" {
		return nil, OrderStatus{}, 0, ErrInvalid
	}
	p := orderPayload{State: "request-pending", Fingerprint: account.Fingerprint, Started: time.Now().UTC().Format("2006-01-02T15:04:05Z"), Domains: s.Domains, RenewalSource: fingerprint}
	return sealOrder(key, id, m, p, "acme-renewal-started")
}
