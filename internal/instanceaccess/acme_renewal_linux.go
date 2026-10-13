//go:build linux

package instanceaccess

import (
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"path/filepath"
)

func ReadStagingRenewalSource(path string, key, id []byte, revision [32]byte, expected uint64, fingerprint string) (inventorystore.RenewalSource, uint64, error) {
	var s inventorystore.RenewalSource
	var gen uint64
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil {
			return err
		}
		s, gen, err = inventorystore.ReadStagingRenewalSource(key, id, image, expected, fingerprint)
		return err
	})
	if err != nil {
		return inventorystore.RenewalSource{}, 0, err
	}
	return s, gen, nil
}

func ReadStagingRenewalResult(path string, key, id []byte, revision [32]byte, expected uint64) (*inventorystore.RenewalResult, uint64, error) {
	var result *inventorystore.RenewalResult
	var gen uint64
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil {
			return err
		}
		result, gen, err = inventorystore.ReadStagingRenewalResult(key, id, image, expected)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return result, gen, nil
}
