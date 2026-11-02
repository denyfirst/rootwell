//go:build linux

package instanceaccess

import (
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func ReadProductionAccount(path string, key, id []byte, revision [32]byte) (inventorystore.AccountStatus, uint64, error) {
	var status inventorystore.AccountStatus
	var generation uint64
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil {
			return err
		}
		status, generation, err = inventorystore.ReadProductionAccount(key, id, image)
		if err != nil {
			return err
		}
		return checkInventoryRevision(path, revision)
	})
	if err != nil {
		return inventorystore.AccountStatus{}, 0, err
	}
	return status, generation, nil
}

func PrepareProductionAccount(path string, key, id []byte, revision [32]byte, expected uint64, permit func() bool) (inventorystore.AccountStatus, uint64, error) {
	var status inventorystore.AccountStatus
	var generation uint64
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		if permit == nil || !permit() {
			return ErrStaleUpgrade
		}
		inventoryPath := filepath.Join(filepath.Dir(path), inventoryName)
		image, err := readInventory(inventoryPath)
		if err != nil {
			return err
		}
		next, prepared, gen, err := inventorystore.PrepareProductionAccount(key, id, image, expected)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		if err := replaceInventory(inventoryPath, next); err != nil {
			return err
		}
		status, generation = prepared, gen
		return nil
	})
	if err != nil {
		return inventorystore.AccountStatus{}, 0, err
	}
	return status, generation, nil
}
