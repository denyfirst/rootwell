//go:build linux

package instanceaccess

import (
	"crypto"
	"path/filepath"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

// Trusted connector only, not a certificate-upload or configurable-trust API.
type CertificateOperation func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (acmestaging.CertificateObservation, error)

type certificateCompletion func([]byte, []byte, []byte, uint64, [][]byte) ([]byte, inventorystore.IssuanceStatus, uint64, error)

func RunStagingCertificate(path string, key, id []byte, revision [32]byte, expected uint64, refresh bool, permit func() bool, use CertificateOperation) (inventorystore.IssuanceStatus, uint64, error) {
	return runStagingCertificate(path, key, id, revision, expected, refresh, permit, use, inventorystore.FinishStagingIssuance)
}

// One lock spans durable intent, single-use lease, bounded fetch, independent
// receipt recheck and atomic pair save. Never call the standalone completion
// writer here: it would reenter this lock. The unexported completion seam is
// for synthetic transaction tests only; production has exactly one fixed Check.
func runStagingCertificate(path string, key, id []byte, revision [32]byte, expected uint64, refresh bool, permit func() bool, use CertificateOperation, finish certificateCompletion) (inventorystore.IssuanceStatus, uint64, error) {
	var status inventorystore.IssuanceStatus
	var generation uint64
	err := withAccessWriteLock(path, func() error {
		if permit == nil || !permit() || use == nil || finish == nil {
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
		permit, err = stagingProviderPermit(key, id, image, permit)
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
		var receipt acmestaging.CertificateObservation
		var savedExpiry string
		var transportError error
		err = inventorystore.WithStagingIssuance(key, id, image, gen, attempt, func(signer crypto.Signer, account, order, expires string, names []string, private, csr []byte, readOnly bool) error {
			if !permit() {
				return ErrStaleUpgrade
			}
			savedExpiry = expires
			receipt, transportError = use(signer, account, order, expires, names, private, csr, readOnly)
			return transportError
		})
		if err != nil {
			// Keep the model's fixed uncertainty error; only bounded typed
			// transport metadata may cross its error-redaction boundary.
			return saveCAFailureWait(path, key, id, image, gen, permit, err, transportError)
		}
		for _, der := range receipt.DER {
			defer clear(der)
		}
		validDeadline := func() bool {
			if !permit() {
				return false
			}
			now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
			return acmeorder.Time(receipt.Expires) && receipt.Expires <= savedExpiry && now < receipt.Expires
		}
		if !validDeadline() {
			return inventorystore.ErrIssuanceUncertain
		}
		if !receipt.Wait.NotBefore.IsZero() || receipt.Wait.Blocked {
			image, err = inventorystore.ConstrainStagingCAWait(key, id, image, gen, receipt.Wait)
			if err != nil {
				return err
			}
		}
		image, err = inventorystore.ConstrainStagingIssuance(key, id, image, gen, receipt.Expires)
		if err != nil {
			return err
		}
		if receipt.State == "certificate-received" {
			next, status, generation, err = finish(key, id, image, gen, receipt.DER)
		} else {
			// No bytes/claimed trust on non-issued observations. The first
			// attempt may only observe processing; reads may observe other states.
			if len(receipt.DER) != 0 || (!refresh && receipt.State != "processing") {
				return inventorystore.ErrIssuanceUncertain
			}
			next, status, generation, err = inventorystore.ObserveStagingIssuance(key, id, image, gen, receipt.State)
		}
		if err != nil {
			return err
		}
		// A shortened CA deadline, cancellation or logout during crypto cannot
		// publish a late acceptance. The already durable intent remains.
		if !validDeadline() || time.Now().UTC().Format("2006-01-02T15:04:05Z") < status.CheckedAt {
			return inventorystore.ErrIssuanceUncertain
		}
		return replaceInventory(store, next)
	})
	if err != nil {
		return inventorystore.IssuanceStatus{}, 0, err
	}
	return status, generation, nil
}
