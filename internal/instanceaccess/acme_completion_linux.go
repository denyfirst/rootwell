//go:build linux

package instanceaccess

import (
	"path/filepath"
	"time"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

// Trusted internal receipt only; no HTTP upload or live transport wiring. The
// acceptance check runs again under the private writer lock before one commit.
func CompleteStagingIssuance(path string, key, id []byte, revision [32]byte, expected uint64, response [][]byte, permit func() bool) (inventorystore.IssuanceStatus, uint64, error) {
	var status inventorystore.IssuanceStatus
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
		next, s, g, err := inventorystore.FinishStagingIssuance(key, id, image, expected, response)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		order, _, err := inventorystore.ReadStagingOrder(key, id, next)
		now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
		if err != nil || now < s.CheckedAt || now >= order.Expires {
			return inventorystore.ErrInvalid
		}
		if err := replaceInventory(store, next); err != nil {
			return err
		}
		status, gen = s, g
		return nil
	})
	if err != nil {
		return inventorystore.IssuanceStatus{}, 0, err
	}
	return status, gen, nil
}
