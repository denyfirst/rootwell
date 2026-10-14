//go:build linux

package instanceaccess

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

const localDNSZoneID = "0123456789abcdef0123456789abcdef"
const localDNSToken = "synthetic-only-credential-not-a-real-token-1234567890"

func TestLinuxCloudflareConfigPermissionsRevisionRefusalFullRestoreAndRecovery(t *testing.T) {
	path, password, code, key, id, _ := inventoryFixture(t)
	defer clear(key)
	revision, err := Revision(path)
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		expected uint64
		revision [32]byte
		permit   func() bool
	}{
		{2, revision, func() bool { return true }}, {1, [32]byte{}, func() bool { return true }},
		{1, revision, nil}, {1, revision, func() bool { return false }},
		{1, revision, func() func() bool { calls := 0; return func() bool { calls++; return calls == 1 } }()},
	} {
		s, gen, err := ChangeCloudflareConfig(path, key, id, tc.revision, tc.expected, localDNSZoneID, "example.com", []byte(localDNSToken), false, tc.permit)
		if err == nil || s.State != "" || gen != 0 {
			t.Fatal("refused credential write produced output")
		}
		after, _ := readInventory(store)
		if !bytes.Equal(before, after) {
			t.Fatal("refused credential write changed image")
		}
	}
	if err := withAccessWriteLock(path, func() error {
		_, _, err := ChangeCloudflareConfig(path, key, id, revision, 1, localDNSZoneID, "example.com", []byte(localDNSToken), false, func() bool { return true })
		if !errors.Is(err, ErrAccessBusy) {
			t.Fatal("second writer entered credential storage")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, gen, err := ChangeCloudflareConfig(path, key, id, revision, 1, localDNSZoneID, "example.com", []byte(localDNSToken), false, func() bool { return true })
	if err != nil || gen != 2 || s.State != "saved" {
		t.Fatal("valid credential write failed")
	}
	if info, err := os.Lstat(store); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("unsafe credential file permissions")
	}
	image, _ := readInventory(store)
	if bytes.Contains(image, []byte(localDNSToken)) {
		t.Fatal("plaintext credential on disk")
	}
	backup := filepath.Join(privateSnapshotDir(t), "dns.rwfull")
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
		const recovered = "a separate sufficiently long recovered DNS password"
		if _, err := RecoverPassword(fresh, code, recovered); err != nil {
			t.Fatal(err)
		}
		newKey, newID, err := OpenWithIdentity(fresh, recovered)
		if err != nil {
			t.Fatal(err)
		}
		newRevision, err := Revision(fresh)
		if err != nil {
			t.Fatal(err)
		}
		restored, got, err := ReadCloudflareConfig(fresh, newKey, newID, newRevision)
		clear(newKey)
		if err != nil || got != 2 || restored != s {
			t.Fatal("full restore/recovery lost credential configuration")
		}
		// Exact complete-image equality proves the sealed token, not only metadata,
		// survived both credential unlock paths and password recovery unchanged.
		restoredImage, err := readInventory(filepath.Join(filepath.Dir(fresh), inventoryName))
		if err != nil || !bytes.Equal(image, restoredImage) {
			t.Fatal("restore changed encrypted token bytes")
		}
	}
	if err := os.Chmod(store, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadCloudflareConfig(path, key, id, revision); err == nil {
		t.Fatal("unsafe permission read accepted")
	}
}

func TestLinuxCloudflareConfigDiskFaultKeepsOldImageAndUncertainSaveReconciles(t *testing.T) {
	path, _, _, key, id, _ := inventoryFixture(t)
	defer clear(key)
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, _ := readInventory(store)
	next, status, _, err := inventorystore.ChangeCloudflareConfig(key, id, before, 1, localDNSZoneID, "example.com", []byte(localDNSToken), false)
	if err != nil {
		t.Fatal(err)
	}
	err = replaceInventoryWithHooks(store, next, func(f *os.File, _ []byte) error { _, _ = f.Write([]byte("partial")); return syscall.ENOSPC }, syncAccessDirectory)
	if err == nil {
		t.Fatal("disk-full credential write succeeded")
	}
	after, _ := readInventory(store)
	if !bytes.Equal(before, after) {
		t.Fatal("pre-rename failure changed image")
	}
	err = replaceInventoryWithSync(store, next, func(string) error { return errors.New("synthetic fsync failure") })
	if !errors.Is(err, ErrInventoryUncertain) {
		t.Fatal("post-rename failure not uncertain")
	}
	committed, _ := readInventory(store)
	actual, gen, err := inventorystore.ReadCloudflareConfig(key, id, committed)
	if err != nil || gen != 2 || actual != status {
		t.Fatal("uncertain saved configuration cannot reconcile")
	}
}
