//go:build linux

package instanceaccess

import (
	"path/filepath"
	"time"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

// One lock, one complete authenticated image; not a stitched multi-read view.
func ReadAutomationStatus(path string, key, id []byte, revision [32]byte, at time.Time) (inventorystore.AutomationStatus, error) {
	var result inventorystore.AutomationStatus
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil {
			return err
		}
		result, err = inventorystore.ReadAutomationStatus(key, id, image, at)
		if err != nil {
			return err
		}
		return checkInventoryRevision(path, revision)
	})
	if err != nil {
		return inventorystore.AutomationStatus{}, err
	}
	return result, nil
}
