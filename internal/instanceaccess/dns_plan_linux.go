//go:build linux

package instanceaccess

import (
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

func ReadStagingDNSPlan(path string, key, id []byte, revision [32]byte) (inventorystore.DNSPlanStatus, uint64, error) {
	var status inventorystore.DNSPlanStatus
	var gen uint64
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil {
			return err
		}
		status, gen, err = inventorystore.ReadStagingDNSPlan(key, id, image)
		return err
	})
	return status, gen, err
}

// Internal custody only: no token borrower, connector, HTTP route or scheduler.
// The trusted future API must supply fresh authentication and explicit consent.
func PrepareStagingDNSPlan(path string, key, id []byte, revision [32]byte, expected uint64, permit func() bool) (inventorystore.DNSPlanStatus, uint64, error) {
	s, _, gen, err := changeDNSPlan(path, key, id, revision, permit, func(image []byte) ([]byte, *inventorystore.DNSAttempt, inventorystore.DNSPlanStatus, uint64, error) {
		next, s, gen, err := inventorystore.PrepareStagingDNSPlan(key, id, image, expected)
		return next, nil, s, gen, err
	})
	return s, gen, err
}
func BeginStagingDNSAttempt(path string, key, id []byte, revision [32]byte, expected uint64, index int, permit func() bool) (*inventorystore.DNSAttempt, inventorystore.DNSPlanStatus, uint64, error) {
	s, attempt, gen, err := changeDNSPlan(path, key, id, revision, permit, func(image []byte) ([]byte, *inventorystore.DNSAttempt, inventorystore.DNSPlanStatus, uint64, error) {
		return inventorystore.BeginStagingDNSAttempt(key, id, image, expected, index)
	})
	return attempt, s, gen, err
}
func DeferStagingDNSAttempt(path string, key, id []byte, revision [32]byte, attempt *inventorystore.DNSAttempt, hint providerretry.Hint, permit func() bool) (inventorystore.DNSPlanStatus, uint64, error) {
	s, _, gen, err := changeDNSPlan(path, key, id, revision, permit, func(image []byte) ([]byte, *inventorystore.DNSAttempt, inventorystore.DNSPlanStatus, uint64, error) {
		next, s, gen, err := inventorystore.DeferStagingDNSAttempt(key, id, image, attempt, hint)
		return next, nil, s, gen, err
	})
	return s, gen, err
}
func changeDNSPlan(path string, key, id []byte, revision [32]byte, permit func() bool, change func([]byte) ([]byte, *inventorystore.DNSAttempt, inventorystore.DNSPlanStatus, uint64, error)) (inventorystore.DNSPlanStatus, *inventorystore.DNSAttempt, uint64, error) {
	var status inventorystore.DNSPlanStatus
	var attempt *inventorystore.DNSAttempt
	var gen uint64
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		if permit == nil || !permit() {
			return ErrStaleUpgrade
		}
		store := filepath.Join(filepath.Dir(path), inventoryName)
		image, err := readInventory(store)
		if err != nil {
			return err
		}
		next, a, s, g, err := change(image)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		if err := replaceInventory(store, next); err != nil {
			return err
		}
		if !permit() {
			return ErrInventoryUncertain
		}
		status, attempt, gen = s, a, g
		return nil
	})
	return status, attempt, gen, err
}
