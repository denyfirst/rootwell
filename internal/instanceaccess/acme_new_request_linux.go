//go:build linux

package instanceaccess

import (
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"path/filepath"
)

func ReadNewStagingRequest(path string, key, id []byte, revision [32]byte) (inventorystore.NewRequestStatus, uint64, error) {
	var status inventorystore.NewRequestStatus
	var gen uint64
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil {
			return err
		}
		status, gen, err = inventorystore.ReadNewStagingRequest(key, id, image)
		return err
	})
	if err != nil {
		return inventorystore.NewRequestStatus{}, 0, err
	}
	return status, gen, nil
}

func CloseStagingRequest(path string, key, id []byte, revision [32]byte, expected uint64, permit func() bool) (inventorystore.NewRequestStatus, uint64, error) {
	var status inventorystore.NewRequestStatus
	var gen uint64
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
		next, s, g, err := inventorystore.CloseStagingRequest(key, id, image, expected)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		if err := replaceInventory(store, next); err != nil {
			return err
		}
		status, gen = s, g
		return nil
	})
	if err != nil {
		return inventorystore.NewRequestStatus{}, 0, err
	}
	return status, gen, nil
}
