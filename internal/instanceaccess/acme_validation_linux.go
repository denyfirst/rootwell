//go:build linux

package instanceaccess

import (
	"crypto"
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type DNSValidationOperation func(crypto.Signer, string, acmeorder.Instructions, []string, bool) (acmeorder.Validation, error)

func RunStagingValidation(accessPath string, key, id []byte, revision [32]byte, expected uint64, refresh bool, permit func() bool, use DNSValidationOperation) (inventorystore.OrderStatus, uint64, error) {
	var status inventorystore.OrderStatus
	var generation uint64
	err := withAccessWriteLock(accessPath, func() error {
		if permit == nil || !permit() || use == nil {
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
		next, _, gen, err := inventorystore.BeginStagingValidation(key, id, image, expected, refresh)
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
		current, _, err := inventorystore.ReadStagingOrder(key, id, image)
		if err != nil {
			return err
		}
		var result acmeorder.Validation
		err = inventorystore.WithStagingOrder(key, id, image, expected, func(signer crypto.Signer, account, order string, names []string) error {
			if !permit() {
				return ErrStaleUpgrade
			}
			var err error
			result, err = use(signer, account, acmeorder.Instructions{URL: order, Expires: current.Expires, Records: current.Records}, names, refresh)
			return err
		})
		if err != nil {
			return err
		}
		next, status, generation, err = inventorystore.FinishStagingValidation(key, id, image, expected, result)
		if err != nil {
			return err
		}
		if !permit() {
			status = inventorystore.OrderStatus{}
			generation = 0
			return ErrStaleUpgrade
		}
		if err := replaceInventory(path, next); err != nil {
			status = inventorystore.OrderStatus{}
			generation = 0
			return err
		}
		return nil
	})
	return status, generation, err
}
