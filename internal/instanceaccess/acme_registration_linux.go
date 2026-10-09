//go:build linux

package instanceaccess

import (
	"crypto"
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

// RunStagingRegistration holds the private writer lock throughout the bounded
// callback. Intent is committed before registration; failures retain that intent
// for explicit same-key reconciliation. No signer escapes through metadata.
func RunStagingRegistration(accessPath string, key, id []byte, revision [32]byte, expected uint64, terms string, reconcile bool, permit func() bool, use func(crypto.Signer, string) (string, bool, error)) (inventorystore.AccountStatus, uint64, error) {
	var status inventorystore.AccountStatus
	var generation uint64
	err := withAccessWriteLock(accessPath, func() error {
		if use == nil || permit == nil || !permit() {
			return ErrStaleUpgrade
		}
		if err := checkInventoryRevision(accessPath, revision); err != nil {
			return err
		}
		path := filepath.Join(filepath.Dir(accessPath), inventoryName)
		image, err := readInventory(path)
		if err != nil {
			return err
		}
		if !reconcile {
			next, _, gen, err := inventorystore.BeginStagingRegistration(key, id, image, expected, terms)
			if err != nil {
				return err
			}
			if !permit() {
				return ErrStaleUpgrade
			}
			if err := replaceInventory(path, next); err != nil {
				return err
			}
			image, expected = next, gen
		} else if terms != "" {
			return inventorystore.ErrInvalid
		}
		var accountURL string
		var absent bool
		err = inventorystore.WithPendingStagingAccount(key, id, image, expected, func(signer crypto.Signer, accepted string) error {
			if !permit() {
				return ErrStaleUpgrade
			}
			var err error
			accountURL, absent, err = use(signer, accepted)
			return err
		})
		if err != nil {
			return err
		}
		// A registration callback must never clear intent by claiming absence.
		if absent && !reconcile {
			return inventorystore.ErrInvalid
		}
		next, prepared, gen, err := inventorystore.FinishStagingRegistration(key, id, image, expected, accountURL, absent)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		if err := replaceInventory(path, next); err != nil {
			return err
		}
		status, generation = prepared, gen
		return nil
	})
	return status, generation, err
}
