//go:build linux

package instanceaccess

import (
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"path/filepath"
)

// ReadStagingOrderPreparation returns one authenticated snapshot, avoiding
// different generations for the public order and public preparation metadata.
func ReadStagingOrderPreparation(path string, key, id []byte, revision [32]byte) (inventorystore.OrderStatus, inventorystore.CertificateRequestStatus, uint64, error) {
	order, request, _, gen, err := ReadStagingOrderLifecycle(path, key, id, revision)
	return order, request, gen, err
}

func ReadStagingOrderLifecycle(path string, key, id []byte, revision [32]byte) (inventorystore.OrderStatus, inventorystore.CertificateRequestStatus, inventorystore.IssuanceStatus, uint64, error) {
	var order inventorystore.OrderStatus
	var request inventorystore.CertificateRequestStatus
	var issuance inventorystore.IssuanceStatus
	var gen uint64
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil {
			return err
		}
		order, gen, err = inventorystore.ReadStagingOrder(key, id, image)
		if err != nil {
			return err
		}
		request, _, err = inventorystore.ReadStagingCertificateRequest(key, id, image)
		if err != nil {
			return err
		}
		issuance, _, err = inventorystore.ReadStagingIssuance(key, id, image)
		return err
	})
	if err != nil {
		return inventorystore.OrderStatus{}, inventorystore.CertificateRequestStatus{}, inventorystore.IssuanceStatus{}, 0, err
	}
	return order, request, issuance, gen, nil
}

func PrepareStagingCertificateRequest(path string, key, id []byte, revision [32]byte, expected uint64, permit func() bool) (inventorystore.CertificateRequestStatus, uint64, error) {
	var status inventorystore.CertificateRequestStatus
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
		next, prepared, generation, err := inventorystore.PrepareStagingCertificateRequest(key, id, image, expected)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		if err := replaceInventory(store, next); err != nil {
			return err
		}
		status, gen = prepared, generation
		return nil
	})
	return status, gen, err
}
