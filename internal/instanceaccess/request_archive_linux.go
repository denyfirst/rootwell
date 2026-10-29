//go:build linux

package instanceaccess

import (
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

// Status and one local repack share the exact private writer/revision boundary.
// No historical key, URI or new CA/DNS authority leaves the store.
func InventoryRequestArchive(path string, key, id []byte, revision [32]byte, expected uint64, permit func() bool) (inventorystore.RequestArchiveStatus, error) {
	var result inventorystore.RequestArchiveStatus
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
		if expected == 0 {
			result, err = inventorystore.ReadRequestArchive(key, id, image)
		} else {
			var next []byte
			next, result, err = inventorystore.ArchiveClosedRequests(key, id, image, expected)
			if err != nil {
				return err
			}
			if !permit() {
				return ErrStaleUpgrade
			}
			if err := checkInventoryRevision(path, revision); err != nil {
				return err
			}
			if err := replaceInventory(store, next); err != nil {
				return err
			}
		}
		if err != nil {
			return err
		}
		if !permit() {
			if expected != 0 {
				return ErrInventoryUncertain
			}
			return ErrStaleUpgrade
		}
		return checkInventoryRevision(path, revision)
	})
	if err != nil {
		return inventorystore.RequestArchiveStatus{}, err
	}
	return result, nil
}
