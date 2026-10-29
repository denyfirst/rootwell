//go:build linux

package instanceaccess

import (
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func ReadRenewalCycle(path string, key, id []byte, rev [32]byte, expected uint64, fp string) (inventorystore.RenewalCycle, error) {
	var result inventorystore.RenewalCycle
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, rev); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil {
			return err
		}
		result, err = inventorystore.ReadRenewalCycle(key, id, image, expected, fp)
		if err != nil {
			return err
		}
		return checkInventoryRevision(path, rev)
	})
	if err != nil {
		return inventorystore.RenewalCycle{}, err
	}
	return result, nil
}
