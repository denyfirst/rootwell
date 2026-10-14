//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

func dnsPlanStoreFixture(t *testing.T) (string, string, string, []byte, []byte, [32]byte) {
	t.Helper()
	path, password, code, key, id, revision := readyOrderStore(t)
	if _, _, err := ChangeCloudflareConfig(path, key, id, revision, 4, localDNSZoneID, "example.com", []byte(localDNSToken), false, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	_, _, err := RunStagingOrder(path, key, id, revision, 5, []string{"example.com"}, false, func() bool { return true }, func(_ crypto.Signer, _, _ string, _ []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		if err := checkpoint(durableOrder); err != nil {
			return acmeorder.Instructions{}, err
		}
		return durableDNS(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return path, password, code, key, id, revision
}
func TestLinuxDNSPlanDurableIntentPermissionsRefusalAndFullRecovery(t *testing.T) {
	path, password, code, key, id, revision := dnsPlanStoreFixture(t)
	defer clear(key)
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, _ := readInventory(store)
	for _, tc := range []struct {
		revision [32]byte
		expected uint64
		permit   func() bool
	}{
		{revision, 7, func() bool { return true }}, {[32]byte{}, 8, func() bool { return true }}, {revision, 8, nil}, {revision, 8, func() bool { return false }},
		{revision, 8, func() func() bool { calls := 0; return func() bool { calls++; return calls == 1 } }()},
	} {
		s, gen, err := PrepareStagingDNSPlan(path, key, id, tc.revision, tc.expected, tc.permit)
		if err == nil || s.Prepared || gen != 0 {
			t.Fatal("refused DNS preparation produced output")
		}
		after, _ := readInventory(store)
		if !bytes.Equal(before, after) {
			t.Fatal("refused preparation changed image")
		}
	}
	if err := withAccessWriteLock(path, func() error {
		_, _, err := PrepareStagingDNSPlan(path, key, id, revision, 8, func() bool { return true })
		if !errors.Is(err, ErrAccessBusy) {
			t.Fatal("concurrent writer entered DNS custody")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, gen, err := PrepareStagingDNSPlan(path, key, id, revision, 8, func() bool { return true })
	if err != nil || gen != 9 || !s.Prepared {
		t.Fatal("durable DNS preparation failed")
	}
	attempt, s, gen, err := BeginStagingDNSAttempt(path, key, id, revision, 9, 0, func() bool { return true })
	if err != nil || gen != 10 || attempt == nil || s.Records[0].Attempts != 1 {
		t.Fatal("durable DNS attempt failed")
	}
	s, gen, err = DeferStagingDNSAttempt(path, key, id, revision, attempt, providerretry.Hint{NotBefore: time.Now().UTC().Add(5 * time.Minute)}, func() bool { return true })
	if err != nil || gen != 11 {
		t.Fatal("durable provider wait failed")
	}
	image, _ := readInventory(store)
	if info, err := os.Lstat(store); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("unsafe DNS custody permissions")
	}
	backup := filepath.Join(privateSnapshotDir(t), "dns-plan.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		credential string
		method     SnapshotUnlock
	}{{password, SnapshotPassword}, {code, SnapshotRecoveryCode}} {
		fresh := filepath.Join(privateSnapshotDir(t), "access.json")
		if err := RestoreFullSnapshot(backup, fresh, tc.credential, tc.method); err != nil {
			t.Fatal(err)
		}
		const recovered = "a separate sufficiently long DNS plan recovery password"
		if _, err := RecoverPassword(fresh, code, recovered); err != nil {
			t.Fatal(err)
		}
		newKey, newID, err := OpenWithIdentity(fresh, recovered)
		if err != nil {
			t.Fatal(err)
		}
		newRevision, _ := Revision(fresh)
		restored, got, err := ReadStagingDNSPlan(fresh, newKey, newID, newRevision)
		if err != nil || got != 11 || !reflect.DeepEqual(restored, s) {
			t.Fatal("restore/recovery lost retry intent")
		}
		if a, out, gen, err := BeginStagingDNSAttempt(fresh, newKey, newID, newRevision, 11, 0, func() bool { return true }); err == nil || a != nil || out.Prepared || gen != 0 {
			t.Fatal("restored early retry allowed")
		}
		clear(newKey)
		restoredImage, _ := readInventory(filepath.Join(filepath.Dir(fresh), inventoryName))
		if !bytes.Equal(image, restoredImage) {
			t.Fatal("restore changed owner/credential/order/attempt bytes")
		}
	}
	if err := os.Chmod(store, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadStagingDNSPlan(path, key, id, revision); err == nil {
		t.Fatal("unsafe DNS store accepted")
	}
}
func TestLinuxDNSPlanFaultAndPostCommitRevocationReturnNoLease(t *testing.T) {
	path, _, _, key, id, revision := dnsPlanStoreFixture(t)
	defer clear(key)
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, _ := readInventory(store)
	next, _, _, err := inventorystore.PrepareStagingDNSPlan(key, id, before, 8)
	if err != nil {
		t.Fatal(err)
	}
	err = replaceInventoryWithHooks(store, next, func(f *os.File, _ []byte) error { _, _ = f.Write([]byte("partial")); return syscall.ENOSPC }, syncAccessDirectory)
	if err == nil {
		t.Fatal("disk-full DNS write succeeded")
	}
	after, _ := readInventory(store)
	if !bytes.Equal(before, after) {
		t.Fatal("pre-rename fault damaged old image")
	}
	err = replaceInventoryWithSync(store, next, func(string) error { return errors.New("synthetic fsync failure") })
	if !errors.Is(err, ErrInventoryUncertain) {
		t.Fatal("post-rename DNS fault not uncertain")
	}
	if s, gen, err := ReadStagingDNSPlan(path, key, id, revision); err != nil || gen != 9 || !s.Prepared {
		t.Fatal("uncertain saved plan cannot reconcile")
	}
	calls := 0
	a, s, gen, err := BeginStagingDNSAttempt(path, key, id, revision, 9, 0, func() bool { calls++; return calls < 3 })
	if !errors.Is(err, ErrInventoryUncertain) || a != nil || s.Prepared || gen != 0 {
		t.Fatal("post-commit revocation returned lease/output")
	}
	if s, gen, err := ReadStagingDNSPlan(path, key, id, revision); err != nil || gen != 10 || s.Records[0].State != "creating" || s.Records[0].Attempts != 1 {
		t.Fatal("uncertain commit forgot intent")
	}
}
