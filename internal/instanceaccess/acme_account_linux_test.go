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

func TestLinuxStagingAccountDurableRefusalsFullRestoreAndRecovery(t *testing.T) {
	path, password, code, key, id, _ := inventoryFixture(t)
	defer clear(key)
	revision, err := Revision(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		expected uint64
		revision [32]byte
		permit   func() bool
	}{
		{2, revision, func() bool { return true }}, {1, [32]byte{}, func() bool { return true }}, {1, revision, nil},
		{1, revision, func() bool { return false }}, {1, revision, func() func() bool { calls := 0; return func() bool { calls++; return calls == 1 } }()},
	} {
		status, gen, err := PrepareStagingAccount(path, key, id, tc.revision, tc.expected, tc.permit)
		if err == nil || status.State != "" || gen != 0 {
			t.Fatal("refused preparation returned result")
		}
		after, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refused preparation wrote image")
		}
	}
	// A cooperating concurrent writer cannot enter custody.
	err = withAccessWriteLock(path, func() error {
		_, _, err := PrepareStagingAccount(path, key, id, revision, 1, func() bool { return true })
		if !errors.Is(err, ErrAccessBusy) {
			t.Fatal("busy writer entered custody")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	status, gen, err := PrepareStagingAccount(path, key, id, revision, 1, func() bool { return true })
	if err != nil || gen != 2 || status.State != "key-prepared" {
		t.Fatal("durable preparation failed")
	}
	if info, err := os.Lstat(filepath.Join(filepath.Dir(path), inventoryName)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("unsafe account store")
	}
	after, _ := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
	if _, _, err := PrepareStagingAccount(path, key, id, revision, 2, func() bool { return true }); !errors.Is(err, inventorystore.ErrAccountExists) {
		t.Fatal("existing account replaced")
	}
	again, _ := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
	if !bytes.Equal(after, again) {
		t.Fatal("duplicate changed account")
	}
	backup := filepath.Join(privateSnapshotDir(t), "account.rwfull")
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
		const recovered = "a separate sufficiently long recovered password"
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
		restored, gen, err := ReadStagingAccount(fresh, newKey, newID, newRevision)
		clear(newKey)
		if err != nil || gen != 2 || restored != status {
			t.Fatal("restore/recovery changed account identity")
		}
	}
	events, gen, err := ReadInventoryHistory(path, key, id, revision)
	if err != nil || gen != 2 || len(events) != 1 || events[0].Action != "acme-key-prepared" || events[0].Fingerprints[0] != status.Fingerprint {
		t.Fatal("durable history lost")
	}
}

func TestLinuxStagingAccountDiskFaultAndUncertainCommit(t *testing.T) {
	path, _, _, key, id, _ := inventoryFixture(t)
	defer clear(key)
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	next, status, _, err := inventorystore.PrepareStagingAccount(key, id, before, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = replaceInventoryWithHooks(store, next, func(f *os.File, _ []byte) error {
		_, _ = f.Write([]byte("partial"))
		return syscall.ENOSPC
	}, syncAccessDirectory)
	if err == nil {
		t.Fatal("disk-full account write succeeded")
	}
	after, err := readInventory(store)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("pre-rename account failure changed image")
	}
	err = replaceInventoryWithSync(store, next, func(string) error { return errors.New("synthetic fsync failure") })
	if !errors.Is(err, ErrInventoryUncertain) {
		t.Fatal("post-rename account fault not uncertain")
	}
	committed, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	actual, gen, err := inventorystore.ReadStagingAccount(key, id, committed)
	if err != nil || gen != 2 || actual != status {
		t.Fatal("uncertain commit could not reconcile same key")
	}
	if err := os.Chmod(store, 0o644); err != nil {
		t.Fatal(err)
	}
	revision, err := Revision(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadStagingAccount(path, key, id, revision); err == nil {
		t.Fatal("unsafe account store permissions accepted")
	}
}
