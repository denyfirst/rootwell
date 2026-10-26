//go:build linux

package instanceaccess

import (
	"path/filepath"

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
// atomic outcome. Only public DER is borrowed. No runtime connector/route is
// enabled yet; future integration must enforce fresh auth, consent and the
// persisted provider-wide wait on ALL CA operations, not just this read.
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
		commit := func(next []byte) error {
			if !permit() {
				return ErrStaleUpgrade
			}
			if err := checkInventoryRevision(path, revision); err != nil {
				return err
			}
			if err := replaceInventory(store, next); err != nil {
				return err
			}
			image = next
			if !permit() {
				return ErrInventoryUncertain
			}
			return nil
		}
		next, attempt, _, _, err := inventorystore.BeginStagingRenewalTiming(key, id, image, expected, fp)
		if err != nil {
			return err
		}
		if err := commit(next); err != nil {
			return err
		}
		next, status, gen, err := inventorystore.ExecuteStagingRenewalTiming(key, id, image, attempt, permit, use)
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
