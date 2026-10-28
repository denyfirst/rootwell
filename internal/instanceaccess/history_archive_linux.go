//go:build linux

package instanceaccess

import (
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"path/filepath"
)

// expected==0 is read-only status. A write requires a live operation permit
// before and after the exact atomic replacement, under the private writer lock.
func InventoryHistoryArchive(path string, key, id []byte, revision [32]byte, expected uint64, permit func() bool) (inventorystore.HistoryArchiveStatus, error) {
	var result inventorystore.HistoryArchiveStatus
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
			result, err = inventorystore.ReadHistoryArchive(key, id, image)
		} else {
			var next []byte
			next, result, err = inventorystore.ArchiveHistory(key, id, image, expected)
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
		return inventorystore.HistoryArchiveStatus{}, err
	}
	return result, nil
}
