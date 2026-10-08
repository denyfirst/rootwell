//go:build linux

package instanceaccess

import (
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func ReadStagingAccount(accessPath string, key, id []byte, revision [32]byte) (inventorystore.AccountStatus, uint64, error) {
	var status inventorystore.AccountStatus
	var generation uint64
	err := withAccessWriteLock(accessPath, func() error {
		if err := checkInventoryRevision(accessPath, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(accessPath), inventoryName))
		if err != nil {
			return err
		}
		status, generation, err = inventorystore.ReadStagingAccount(key, id, image)
		return err
	})
	return status, generation, err
}

// PrepareStagingAccount rechecks live permission under the writer lock just
// before replacement. After that boundary, cancellation cannot undo a commit.
func PrepareStagingAccount(accessPath string, key, id []byte, revision [32]byte, expected uint64, permit func() bool) (inventorystore.AccountStatus, uint64, error) {
	var status inventorystore.AccountStatus
	var generation uint64
	err := withAccessWriteLock(accessPath, func() error {
		if err := checkInventoryRevision(accessPath, revision); err != nil {
			return err
		}
		if permit == nil || !permit() {
			return ErrStaleUpgrade
		}
		path := filepath.Join(filepath.Dir(accessPath), inventoryName)
		image, err := readInventory(path)
		if err != nil {
			return err
		}
		next, prepared, gen, err := inventorystore.PrepareStagingAccount(key, id, image, expected)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		if err := replaceInventory(path, next); err != nil {
			return err
		}
		status, generation = prepared, gen
		return nil
	})
	return status, generation, err
}
