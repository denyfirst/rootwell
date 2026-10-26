//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/providerretry"
	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

func TestLinuxProviderWaitCoversEveryCAPathBeforeIntentAndSurvivesRestore(t *testing.T) {
	path, code, key, id, fp, revision := completedClosureStore(t)
	defer clear(key)
	allow := func() bool { return true }
	if err := RunStagingProviderRead(path, key, id, revision, allow, func(permit func() bool) error {
		if !permit() {
			t.Fatal("legitimate provider read refused")
		}
		if _, _, err := ReadStagingRenewalTiming(path, key, id, revision, 13, fp); !errors.Is(err, ErrAccessBusy) {
			t.Fatal("read released lock")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().Add(3 * time.Hour)
	_, g, err := RunStagingRenewalTiming(path, key, id, revision, 13, fp, allow, func(func() bool, []byte) (renewalrecord.Observation, error) {
		return renewalrecord.Observation{}, &renewalrecord.Failure{Hint: providerretry.Hint{NotBefore: until}}
	})
	if err != nil || g != 15 {
		t.Fatal("wait fixture failed", err)
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, _ := readInventory(store)
	assertBlockedCAPaths(t, path, key, id, revision, g, fp, inventorystore.ErrTimingWait)
	after, _ := readInventory(store)
	if !bytes.Equal(before, after) {
		t.Fatal("blocked provider operation wrote intent")
	}
	backup := filepath.Join(privateSnapshotDir(t), "provider-wait.rwfull")
	if err := ExportFullSnapshot(path, backup, closedGateTestPassword, code); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); err != nil {
		t.Fatal(err)
	}
	rk, ri, err := OpenWithIdentity(fresh, closedGateTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rk)
	rev, _ := Revision(fresh)
	assertBlockedCAPaths(t, fresh, rk, ri, rev, g, fp, inventorystore.ErrTimingWait)
	// Missing or corrupt enrolled storage is never a no-policy fallback.
	current := filepath.Join(filepath.Dir(fresh), inventoryName)
	if err := os.Rename(current, current+".quarantined"); err != nil {
		t.Fatal(err)
	}
	called := false
	use := func(func() bool) error { called = true; return nil }
	if err := RunStagingProviderRead(fresh, rk, ri, rev, allow, use); !errors.Is(err, ErrInventoryMissing) || called {
		t.Fatal("missing enrolled image bypassed wait", err)
	}
	if err := os.WriteFile(current, []byte(`{"malformed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunStagingProviderRead(fresh, rk, ri, rev, allow, use); err == nil || called {
		t.Fatal("malformed enrolled image bypassed wait")
	}
}
func TestLinuxProviderWaitBlockedHintDeniesEveryCAPath(t *testing.T) {
	path, _, key, id, fp, revision := completedClosureStore(t)
	defer clear(key)
	_, gen, err := RunStagingRenewalTiming(path, key, id, revision, 13, fp, func() bool { return true }, func(func() bool, []byte) (renewalrecord.Observation, error) {
		return renewalrecord.Observation{}, &renewalrecord.Failure{Hint: providerretry.Hint{Blocked: true}}
	})
	if err != nil || gen != 15 {
		t.Fatal("blocked fixture failed", err)
	}
	assertBlockedCAPaths(t, path, key, id, revision, gen, fp, inventorystore.ErrTimingBlocked)
}
func assertBlockedCAPaths(t *testing.T, path string, key, id []byte, rev [32]byte, gen uint64, fp string, want error) {
	t.Helper()
	allow := func() bool { return true }
	called := false
	check := func(err error) {
		t.Helper()
		if !errors.Is(err, want) || called {
			t.Fatal("CA path bypassed persisted wait", err)
		}
	}
	check(RunStagingProviderRead(path, key, id, rev, allow, func(func() bool) error { called = true; return nil }))
	_, _, err := RunStagingRegistration(path, key, id, rev, gen, "", true, allow, func(crypto.Signer, string) (string, bool, error) { called = true; return "", false, nil })
	check(err)
	order := func(crypto.Signer, string, string, []string, func(string) error) (acmeorder.Instructions, error) {
		called = true
		return acmeorder.Instructions{}, nil
	}
	_, _, err = RunStagingOrder(path, key, id, rev, gen, nil, true, allow, order)
	check(err)
	_, _, err = RunStagingRenewalOrder(path, key, id, rev, gen, fp, allow, order)
	check(err)
	_, _, err = RunStagingValidation(path, key, id, rev, gen, true, allow, func(crypto.Signer, string, acmeorder.Instructions, []string, bool) (acmeorder.Validation, error) {
		called = true
		return acmeorder.Validation{}, nil
	})
	check(err)
	_, _, err = RunStagingCertificate(path, key, id, rev, gen, true, allow, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (acmestaging.CertificateObservation, error) {
		called = true
		return acmestaging.CertificateObservation{}, nil
	})
	check(err)
	_, _, err = RunStagingRenewalTiming(path, key, id, rev, gen, fp, allow, func(func() bool, []byte) (renewalrecord.Observation, error) {
		called = true
		return renewalrecord.Observation{}, nil
	})
	check(err)
}
