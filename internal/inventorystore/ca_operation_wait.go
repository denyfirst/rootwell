package inventorystore

import (
	"bytes"
	"time"

	"github.com/denyfirst/rootwell/internal/providerretry"
)

// ConstrainStagingCAWait adds only trusted transport metadata to the exact
// pending/result image. It does not advance generation or grant network/replay
// authority. The existing result writer must publish it atomically with its
// checked observation; this intermediate image never leaves the private writer.
func ConstrainStagingCAWait(key, id, image []byte, expected uint64, hint providerretry.Hint) ([]byte, error) {
	return constrainCAWaitAt(key, id, image, expected, hint, time.Now().UTC())
}

func constrainCAWaitAt(key, id, image []byte, expected uint64, hint providerretry.Hint, at time.Time) ([]byte, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, ErrStaleGeneration
	}
	order, err := openOrder(key, id, m)
	if err != nil || order.State == "not-started" || !timingClock(key, id, m, at, nil) {
		return nil, ErrInvalid
	}
	stamp := at.UTC().Format(time.RFC3339)
	issued, err := openIssuance(key, id, m)
	if err != nil || stamp < max(order.Started, order.CheckedAt, issued.StartedAt, issued.CheckedAt) {
		return nil, ErrInvalid
	}
	if hint.NotBefore.IsZero() && !hint.Blocked {
		return bytes.Clone(image), nil
	}
	if err := constrainStagingWait(key, id, &m, hint, at); err != nil {
		return nil, err
	}
	next, err := encode(key, m)
	if err != nil {
		return nil, err
	}
	if _, _, err := decode(key, id, next); err != nil {
		return nil, err
	}
	return next, nil
}

// A failed CA operation cannot publish an observation. Retain only its bounded
// wait and the original pending scope. Capacity must be reserved before I/O;
// inability to publish is uncertainty, never permission to replay a write.
func SaveStagingCAFailureWait(key, id, image []byte, expected uint64, hint providerretry.Hint) ([]byte, uint64, error) {
	constrained, err := ConstrainStagingCAWait(key, id, image, expected, hint)
	if err != nil {
		return nil, 0, err
	}
	if bytes.Equal(image, constrained) {
		return bytes.Clone(image), expected, nil
	}
	m, _, err := decode(key, id, constrained)
	if err != nil {
		return nil, 0, err
	}
	if m.Generation >= maxGeneration {
		return nil, 0, ErrLimit
	}
	account, err := accountStatus(key, id, m)
	if err != nil {
		return nil, 0, err
	}
	m.Generation++
	if err := addEvent(key, &m, "acme-provider-wait-saved", []string{account.Fingerprint}); err != nil {
		return nil, 0, err
	}
	next, err := encode(key, m)
	if err != nil {
		return nil, 0, err
	}
	if _, _, err := decode(key, id, next); err != nil {
		return nil, 0, err
	}
	return next, m.Generation, nil
}
