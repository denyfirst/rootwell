//go:build linux

package instanceaccess

import (
	"path/filepath"
	"time"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

// ReadStagingRenewalTiming is local metadata, not permission to contact a CA.
func ReadStagingRenewalTiming(path string, key, id []byte, revision [32]byte, expected uint64, fp string) (inventorystore.RenewalTimingStatus, uint64, error) {
	var result inventorystore.RenewalTimingStatus
	var generation uint64
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil {
			return err
		}
		result, generation, err = inventorystore.ReadStagingRenewalTiming(key, id, image, expected, fp)
		if err != nil {
			return err
		}
		return checkInventoryRevision(path, revision)
	})
	if err != nil {
		return inventorystore.RenewalTimingStatus{}, 0, err
	}
	return result, generation, nil
}

// RunStagingRenewalTiming holds the private lock through intent-before-I/O and
// atomic outcome. Only public DER is borrowed. ADR0075's explicit API enforces
// fresh auth/consent/budgets; all enrolled-store CA operations enforce the same
// persisted provider-wide wait, not just this read.
func RunStagingRenewalTiming(path string, key, id []byte, revision [32]byte, expected uint64, fp string, permit func() bool, use inventorystore.RenewalTimingOperation) (inventorystore.RenewalTimingStatus, uint64, error) {
	var result inventorystore.RenewalTimingStatus
	var generation uint64
	err := withAccessWriteLock(path, func() error {
		if permit == nil || !permit() || use == nil {
			return ErrStaleUpgrade
		}
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		store := filepath.Join(filepath.Dir(path), inventoryName)
		image, err := readInventory(store)
		if err != nil {
			return err
		}
		started := time.Now().UTC()
		next, attempt, planned, _, err := inventorystore.BeginStagingRenewalTiming(key, id, image, expected, fp)
		if err != nil {
			return err
		}
		expires, err := time.Parse(time.RFC3339, planned.NotAfter)
		if err != nil {
			return inventorystore.ErrInvalid
		}
		allowed := func() bool {
			if !permit() {
				return false
			}
			now := time.Now().UTC()
			return !now.Before(started) && now.Before(started.Add(20*time.Second)) && now.Before(expires)
		}
		commit := func(next []byte) error {
			if !allowed() {
				return ErrStaleUpgrade
			}
			if err := checkInventoryRevision(path, revision); err != nil {
				return err
			}
			if err := replaceInventory(store, next); err != nil {
				return err
			}
			image = next
			if !allowed() {
				return ErrInventoryUncertain
			}
			return nil
		}
		if err := commit(next); err != nil {
			return err
		}
		next, status, gen, err := inventorystore.ExecuteStagingRenewalTiming(key, id, image, attempt, allowed, use)
		if err != nil {
			return err
		}
		if err := commit(next); err != nil {
			return err
		}
		result, generation = status, gen
		return nil
	})
	if err != nil {
		return inventorystore.RenewalTimingStatus{}, 0, err
	}
	return result, generation, nil
}

// Interrupt only retires a local public GET intent. It does not shorten waits,
// cancel a CA order, erase DNS ownership or authorize a replacement operation.
func InterruptStagingRenewalTiming(path string, key, id []byte, revision [32]byte, expected uint64, fp string, permit func() bool) (inventorystore.RenewalTimingStatus, uint64, error) {
	var result inventorystore.RenewalTimingStatus
	var generation uint64
	err := withAccessWriteLock(path, func() error {
		if permit == nil || !permit() {
			return ErrStaleUpgrade
		}
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		store := filepath.Join(filepath.Dir(path), inventoryName)
		image, err := readInventory(store)
		if err != nil {
			return err
		}
		next, status, gen, err := inventorystore.InterruptStagingRenewalTiming(key, id, image, expected, fp)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		if err := replaceInventory(store, next); err != nil {
			return err
		}
		if !permit() {
			return ErrInventoryUncertain
		}
		result, generation = status, gen
		return nil
	})
	if err != nil {
		return inventorystore.RenewalTimingStatus{}, 0, err
	}
	return result, generation, nil
}
