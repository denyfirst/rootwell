//go:build linux

package instanceaccess

import (
	"crypto"
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

// Trusted internal callback only; no route or live connector is wired yet.
// The final boolean is derived by the store lease, not supplied by the callback.
type IssuanceOperation func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (string, error)

func ReadStagingIssuance(path string, key, id []byte, revision [32]byte) (inventorystore.IssuanceStatus, uint64, error) {
	var status inventorystore.IssuanceStatus
	var gen uint64
	err := withAccessWriteLock(path, func() error {
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil {
			return err
		}
		status, gen, err = inventorystore.ReadStagingIssuance(key, id, image)
		return err
	})
	if err != nil {
		return inventorystore.IssuanceStatus{}, 0, err
	}
	return status, gen, err
}

// Caller must provide fresh-auth/consent, live permission and provider budgets.
// The private lock spans intent commit, single-use lease and observation commit.
// A failed/lost result retains durable intent and cannot authorize another first
// attempt. Only same-order reads are possible on every later invocation.
func RunStagingIssuance(path string, key, id []byte, revision [32]byte, expected uint64, refresh bool, permit func() bool, use IssuanceOperation) (inventorystore.IssuanceStatus, uint64, error) {
	var status inventorystore.IssuanceStatus
	var generation uint64
	err := withAccessWriteLock(path, func() error {
		if permit == nil || !permit() || use == nil {
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
		next, attempt, _, gen, err := inventorystore.BeginStagingIssuance(key, id, image, expected, refresh)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		if next != nil {
			if err := replaceInventory(store, next); err != nil {
				return err
			}
			image = next
		}
		observation := ""
		err = inventorystore.WithStagingIssuance(key, id, image, gen, attempt, func(signer crypto.Signer, account, order, expires string, names []string, private, csr []byte, readOnly bool) error {
			if !permit() {
				return ErrStaleUpgrade
			}
			var callbackErr error
			observation, callbackErr = use(signer, account, order, expires, names, private, csr, readOnly)
			return callbackErr
		})
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		// First-attempt transport can only return a checked processing observation
		// here. Certificate-received is deliberately NOT an observation verdict.
		if !refresh && observation != "processing" {
			return inventorystore.ErrIssuanceUncertain
		}
		next, observed, finalGen, err := inventorystore.ObserveStagingIssuance(key, id, image, gen, observation)
		if err != nil {
			return err
		}
		if !permit() {
			return ErrStaleUpgrade
		}
		if err := replaceInventory(store, next); err != nil {
			return err
		}
		status, generation = observed, finalGen
		return nil
	})
	if err != nil {
		return inventorystore.IssuanceStatus{}, 0, err
	}
	return status, generation, nil
}
