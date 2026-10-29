//go:build linux

package instanceaccess

import (
	"path/filepath"
	"time"

	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

// RunStagingDNS holds the private writer lock across preparation, intent,
// secret borrowing, bounded network and atomic observation. Fresh password and
// explicit consent are required at the API boundary, not implied by this method.
func RunStagingDNS(path string, key, id []byte, revision [32]byte, expected uint64, index int, mode string, permit func() bool, use inventorystore.DNSOperation) (inventorystore.DNSPlanStatus, uint64, error) {
	if mode == "maintenance" {
		return inventorystore.DNSPlanStatus{}, 0, inventorystore.ErrInvalid
	}
	return runStagingDNS(path, key, id, revision, expected, index, mode, permit, use)
}

// Separate entry point: a scheduler's ordinary DNS capability cannot invoke it.
// Only the fresh-auth, reviewed-scope operator API is an approved caller.
func RunOperatorDNSMaintenance(path string, key, id []byte, revision [32]byte, expected uint64, index int, permit func() bool, use inventorystore.DNSOperation) (inventorystore.DNSPlanStatus, uint64, error) {
	return runStagingDNS(path, key, id, revision, expected, index, "maintenance", permit, use)
}

func runStagingDNS(path string, key, id []byte, revision [32]byte, expected uint64, index int, mode string, permit func() bool, use inventorystore.DNSOperation) (inventorystore.DNSPlanStatus, uint64, error) {
	var status inventorystore.DNSPlanStatus
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
		s, gen, err := inventorystore.ReadStagingDNSPlan(key, id, image)
		if err != nil {
			return err
		}
		if expected == 0 || gen != expected {
			return inventorystore.ErrStaleGeneration
		}
		commit := func(next []byte) error {
			if !permit() {
				return ErrStaleUpgrade
			}
			if err := replaceInventory(store, next); err != nil {
				return err
			}
			image = next
			if !permit() {
				return ErrInventoryUncertain
			}
			return nil
		}
		if !s.Prepared {
			if mode != "add" {
				return inventorystore.ErrInvalid
			}
			next, prepared, g, err := inventorystore.PrepareStagingDNSPlan(key, id, image, gen)
			if err != nil {
				return err
			}
			if index < 0 || index >= len(prepared.Records) {
				return inventorystore.ErrInvalid
			}
			if err := commit(next); err != nil {
				return err
			}
			gen = g
		}
		next, attempt, planned, _, err := inventorystore.BeginStagingDNSOperation(key, id, image, gen, index, mode)
		if err != nil {
			return err
		}
		if err := commit(next); err != nil {
			return err
		}
		// Only first creation is time-limited by the CA. Read-only reconciliation
		// and cleanup deliberately survive its expiry, without CA authority.
		allowed := func() bool {
			return permit() && (mode != "add" || planned.Records[index].Attempts > 1 || time.Now().UTC().Format("2006-01-02T15:04:05Z") < planned.Expires)
		}
		next, s, g, err := inventorystore.ExecuteStagingDNSAttempt(key, id, image, attempt, allowed, func(operationPermit func() bool, token []byte, scope dnsrecord.Scope, state dnsrecord.State, cleanup, readOnly bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
			if !allowed() {
				return dnsrecord.State{}, ErrStaleUpgrade
			}
			return use(operationPermit, token, scope, state, cleanup, readOnly, checkpoint)
		})
		if err != nil {
			return err
		}
		if !allowed() {
			return ErrInventoryUncertain
		}
		if err := commit(next); err != nil {
			return err
		}
		if !allowed() {
			return ErrInventoryUncertain
		}
		status, generation = s, g
		return nil
	})
	if err != nil {
		return inventorystore.DNSPlanStatus{}, 0, err
	}
	return status, generation, nil
}
