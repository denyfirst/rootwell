//go:build linux

package instanceaccess

import (
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func ReadCloudflareConfig(accessPath string, key, id []byte, revision [32]byte) (inventorystore.CloudflareStatus, uint64, error) {
	var status inventorystore.CloudflareStatus
	var generation uint64
	err := withAccessWriteLock(accessPath, func() error {
		if err := checkInventoryRevision(accessPath, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(accessPath), inventoryName))
		if err != nil {
			return err
		}
		status, generation, err = inventorystore.ReadCloudflareConfig(key, id, image)
		return err
	})
	return status, generation, err
}

func ChangeCloudflareConfig(accessPath string, key, id []byte, revision [32]byte, expected uint64, zoneID, zoneName string, token []byte, remove bool, permit func() bool) (inventorystore.CloudflareStatus, uint64, error) {
	var status inventorystore.CloudflareStatus
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
		next, saved, gen, err := inventorystore.ChangeCloudflareConfig(key, id, image, expected, zoneID, zoneName, token, remove)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		if err := replaceInventory(path, next); err != nil {
			return err
		}
		status, generation = saved, gen
		return nil
	})
	return status, generation, err
}
