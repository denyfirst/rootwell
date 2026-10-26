//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"time"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

// Called only while holding the private writer lock. Cache authenticated public
// wait metadata, not keys or an unlocked credential. The same lock prevents a
// concurrent provider result from changing this barrier during outbound work.
func stagingProviderPermit(key, id, image []byte, permit func() bool) (func() bool, error) {
	if permit == nil || !permit() {
		return nil, ErrStaleUpgrade
	}
	started := time.Now().UTC()
	wait, _, err := inventorystore.ReadStagingProviderWait(key, id, image)
	if err != nil {
		return nil, err
	}
	if wait.Blocked {
		return nil, inventorystore.ErrTimingBlocked
	}
	if !wait.Ready {
		return nil, inventorystore.ErrTimingWait
	}
	var notBefore time.Time
	if wait.NotBefore != "" {
		notBefore, err = time.Parse(time.RFC3339Nano, wait.NotBefore)
		if err != nil {
			return nil, inventorystore.ErrInvalid
		}
	}
	allowed := func() bool {
		if !permit() {
			return false
		}
		now := time.Now().UTC()
		return !now.Before(started) && !now.Before(notBefore) && now.Year() >= 2020 && now.Year() <= 2100
	}
	if !allowed() {
		return nil, ErrStaleUpgrade
	}
	return allowed, nil
}

// Covers directory/terms reads on enrolled stores under the same lock/barrier
// as order/issuance writers. Callback results remain private until this returns.
func RunStagingProviderRead(path string, key, id []byte, revision [32]byte, permit func() bool, use func(func() bool) error) error {
	return withAccessWriteLock(path, func() error {
		if use == nil {
			return ErrStaleUpgrade
		}
		if err := checkInventoryRevision(path, revision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		var allowed func() bool
		if errors.Is(err, ErrInventoryMissing) {
			// A ready identity is not recovery/storage enrollment. Only a
			// revision-bound v2 envelope with NO image can use the legacy
			// directory-only path. Never treat missing v3 storage as no wait.
			body, readErr := readAccess(path)
			e, parseErr := parseEnvelope(body)
			if readErr != nil || parseErr != nil || sha256.Sum256(body) != revision || e.Version != 2 || e.State != ready || len(key) != 32 || !bytes.Equal(e.InstallationID, id) || permit == nil || !permit() {
				return ErrInventoryMissing
			}
			started := time.Now().UTC()
			allowed = func() bool {
				if !permit() {
					return false
				}
				now := time.Now().UTC()
				return !now.Before(started) && now.Year() >= 2020 && now.Year() <= 2100
			}
		} else if err != nil {
			return err
		} else {
			allowed, err = stagingProviderPermit(key, id, image, permit)
			if err != nil {
				return err
			}
		}
		if !allowed() {
			return ErrStaleUpgrade
		}
		if err := use(allowed); err != nil {
			return err
		}
		if !allowed() {
			return ErrStaleUpgrade
		}
		return checkInventoryRevision(path, revision)
	})
}
