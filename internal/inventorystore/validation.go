package inventorystore

import (
	"slices"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
)

// Every attempt (including read-only refresh) invalidates a previous verdict
// durably before outbound I/O. Only the first acknowledged attempt may Accept.
func BeginStagingValidation(key, id, image []byte, expected uint64, refresh bool) ([]byte, OrderStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, OrderStatus{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, OrderStatus{}, 0, ErrStaleGeneration
	}
	if len(m.ACMEIssuances) != 0 {
		return nil, OrderStatus{}, 0, ErrInvalid
	}
	p, err := openOrder(key, id, m)
	if err != nil || (!refresh && p.State != "dns-acknowledged") || (refresh && !acmeorder.ValidationStarted(p.State)) || p.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") {
		return nil, OrderStatus{}, 0, ErrInvalid
	}
	if m.Generation > maxGeneration-2 || len(m.History) > maxHistory-2 {
		return nil, OrderStatus{}, 0, ErrLimit
	}
	p.State, p.Validation, p.CheckedAt = "validation-pending", nil, ""
	return sealOrder(key, id, m, p, "acme-validation-started")
}

func FinishStagingValidation(key, id, image []byte, expected uint64, result acmeorder.Validation) ([]byte, OrderStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, OrderStatus{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, OrderStatus{}, 0, ErrStaleGeneration
	}
	p, err := openOrder(key, id, m)
	state := acmeorder.ValidationState(result, p.Domains)
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if err != nil || p.State != "validation-pending" || state == "" || result.URL != p.URL || result.Expires > p.Expires || result.Expires <= now {
		return nil, OrderStatus{}, 0, ErrInvalid
	}
	result.Statuses = slices.Clone(result.Statuses)
	p.State, p.Expires, p.Validation, p.CheckedAt = state, result.Expires, &result, now
	return sealOrder(key, id, m, p, "acme-validation-observed")
}
