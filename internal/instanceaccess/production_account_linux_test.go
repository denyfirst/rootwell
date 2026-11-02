//go:build linux

package instanceaccess

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func TestLinuxProductionAccountSeparateCustodyRefusalsAndFullRecovery(t *testing.T) {
	path, password, code, key, id, _ := inventoryFixture(t)
	defer clear(key)
	rev, err := Revision(path)
	if err != nil {
		t.Fatal(err)
	}
	stage, g, err := PrepareStagingAccount(path, key, id, rev, 1, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		rev      [32]byte
		expected uint64
		permit   func() bool
	}{
		{rev, g + 1, func() bool { return true }}, {[32]byte{}, g, func() bool { return true }}, {rev, g, nil}, {rev, g, func() bool { return false }},
		{rev, g, func() func() bool { calls := 0; return func() bool { calls++; return calls == 1 } }()},
	} {
		status, gen, err := PrepareProductionAccount(path, key, id, tc.rev, tc.expected, tc.permit)
		if err == nil || status != (inventorystore.AccountStatus{}) || gen != 0 {
			t.Fatal("refusal returned partial result")
		}
		after, err := readInventory(store)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refused write changed storage")
		}
	}
	err = withAccessWriteLock(path, func() error {
		_, _, err := PrepareProductionAccount(path, key, id, rev, g, func() bool { return true })
		if !errors.Is(err, ErrAccessBusy) {
			t.Fatal("busy writer entered production custody")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	status, gen, err := PrepareProductionAccount(path, key, id, rev, g, func() bool { return true })
	if err != nil || gen != g+1 || status.Fingerprint == stage.Fingerprint || status.Registration != "not-registered" {
		t.Fatal("independent production key not saved", err)
	}
	if info, err := os.Lstat(store); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe production storage")
	}
	got, _, err := ReadStagingAccount(path, key, id, rev)
	if err != nil || got != stage {
		t.Fatal("staging identity changed")
	}
	if _, _, err := PrepareProductionAccount(path, key, id, rev, gen, func() bool { return true }); !errors.Is(err, inventorystore.ErrProductionAccountExists) {
		t.Fatal("production key replaced")
	}
	backup := filepath.Join(privateSnapshotDir(t), "production-account.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); err != nil {
		t.Fatal(err)
	}
	const recovered = "a distinct sufficiently long recovered production test password"
	if _, err := RecoverPassword(fresh, code, recovered); err != nil {
		t.Fatal(err)
	}
	newKey, newID, err := OpenWithIdentity(fresh, recovered)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(newKey)
	newRev, err := Revision(fresh)
	if err != nil {
		t.Fatal(err)
	}
	restored, restoredGen, err := ReadProductionAccount(fresh, newKey, newID, newRev)
	if err != nil || restored != status || restoredGen != gen {
		t.Fatal("full recovery lost production key", err)
	}
	got, _, err = ReadStagingAccount(fresh, newKey, newID, newRev)
	if err != nil || got != stage {
		t.Fatal("full recovery mixed environments", err)
	}
}
