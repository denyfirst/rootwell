//go:build linux

package instanceaccess

import (
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"path/filepath"
	"time"
)

func ReadTimingReadiness(path string, key, id []byte, rev [32]byte, expected uint64, fp string, at time.Time) (inventorystore.TimingReadiness, error) {
	var result inventorystore.TimingReadiness
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, rev); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil {
			return err
		}
		result, err = inventorystore.ReadTimingReadiness(key, id, image, expected, fp, at)
		if err != nil {
			return err
		}
		return checkInventoryRevision(path, rev)
	})
	if err != nil {
		return inventorystore.TimingReadiness{}, err
	}
	return result, nil
}
