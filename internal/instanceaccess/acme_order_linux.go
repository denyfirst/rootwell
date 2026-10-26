//go:build linux

package instanceaccess

import (
	"crypto"
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type DNSOrderOperation func(crypto.Signer, string, string, []string, func(string) error) (acmeorder.Instructions, error)

func ReadStagingOrder(accessPath string, key, id []byte, revision [32]byte) (inventorystore.OrderStatus, uint64, error) {
	var status inventorystore.OrderStatus
	var generation uint64
	err := withAccessWriteLock(accessPath, func() error {
		if err := checkInventoryRevision(accessPath, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(accessPath), inventoryName))
		if err != nil {
			return err
		}
		status, generation, err = inventorystore.ReadStagingOrder(key, id, image)
		return err
	})
	return status, generation, err
}

// A single lock covers intent, network, checkpoint and instructions. A failed
// request leaves the most recent durable state, never authorizes recreation.
func RunStagingOrder(accessPath string, key, id []byte, revision [32]byte, expected uint64, names []string, resume bool, permit func() bool, use DNSOrderOperation) (inventorystore.OrderStatus, uint64, error) {
	return runStagingOrder(accessPath, key, id, revision, expected, names, resume, "", permit, use)
}

func RunStagingRenewalOrder(accessPath string, key, id []byte, revision [32]byte, expected uint64, fingerprint string, permit func() bool, use DNSOrderOperation) (inventorystore.OrderStatus, uint64, error) {
	if fingerprint == "" {
		return inventorystore.OrderStatus{}, 0, inventorystore.ErrInvalid
	}
	return runStagingOrder(accessPath, key, id, revision, expected, nil, false, fingerprint, permit, use)
}

func runStagingOrder(accessPath string, key, id []byte, revision [32]byte, expected uint64, names []string, resume bool, source string, permit func() bool, use DNSOrderOperation) (inventorystore.OrderStatus, uint64, error) {
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
		permit, err = stagingProviderPermit(key, id, image, permit)
		if err != nil {
			return err
		}
		if resume {
			if len(names) != 0 {
				return inventorystore.ErrInvalid
			}
			current, gen, err := inventorystore.ReadStagingOrder(key, id, image)
			if err != nil {
				return err
			}
			if expected == 0 || gen != expected {
				return inventorystore.ErrStaleGeneration
			}
			if current.State != "order-known" && current.State != "dns-ready" && current.State != "dns-acknowledged" {
				return inventorystore.ErrInvalid
			}
		} else {
			var next []byte
			var gen uint64
			if source != "" {
				next, _, gen, err = inventorystore.BeginStagingRenewal(key, id, image, expected, source)
			} else {
				next, _, gen, err = inventorystore.BeginStagingOrder(key, id, image, expected, names)
			}
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
		}
		checkpointed := resume
		checkpoint := func(url string) error {
			if checkpointed || !permit() {
				return ErrStaleUpgrade
			}
			next, _, gen, err := inventorystore.UpdateStagingOrder(key, id, image, expected, url, nil, false)
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
			checkpointed = true
			return nil
		}
		var info acmeorder.Instructions
		err = inventorystore.WithStagingOrder(key, id, image, expected, func(signer crypto.Signer, account, order string, names []string) error {
			if !permit() {
				return ErrStaleUpgrade
			}
			var err error
			info, err = use(signer, account, order, names, checkpoint)
			return err
		})
		if err != nil {
			return err
		}
		if !checkpointed {
			return inventorystore.ErrInvalid
		}
		next, ready, gen, err := inventorystore.UpdateStagingOrder(key, id, image, expected, "", &info, false)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		if err := replaceInventory(path, next); err != nil {
			return err
		}
		status, generation = ready, gen
		return nil
	})
	return status, generation, err
}

func AcknowledgeStagingDNS(accessPath string, key, id []byte, revision [32]byte, expected uint64, permit func() bool) (inventorystore.OrderStatus, uint64, error) {
	var status inventorystore.OrderStatus
	var generation uint64
	err := withAccessWriteLock(accessPath, func() error {
		if permit == nil || !permit() {
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
		next, ready, gen, err := inventorystore.UpdateStagingOrder(key, id, image, expected, "", nil, true)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		if err := replaceInventory(path, next); err != nil {
			return err
		}
		status, generation = ready, gen
		return nil
	})
	return status, generation, err
}
