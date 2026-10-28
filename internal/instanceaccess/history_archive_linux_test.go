//go:build linux

package instanceaccess

import (
	"bytes"
	"errors"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLinuxHistoryArchiveAtomicRetainedAndFullRestore(t *testing.T) {
	path, password, code, key, id, _ := inventoryFixture(t)
	defer clear(key)
	rev, _ := Revision(path)
	cert, _ := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	rows, _, err := AppendInventory(path, key, id, rev, cert, "owner", "service")
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	image, _ := readInventory(store)
	for gen := uint64(2); gen <= 512; gen++ {
		image, _, _, err = inventorystore.UpdateOwner(key, id, image, rows[0].Fingerprint, string(rune(1000+gen)), gen)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := replaceInventory(store, image); err != nil {
		t.Fatal(err)
	}
	before, _, _ := inventorystore.History(key, id, image)
	permit := func() bool { return true }
	status, err := InventoryHistoryArchive(path, key, id, rev, 0, permit)
	if err != nil || !status.CanArchive || status.Active != 512 {
		t.Fatal("valid status refused", err, status)
	}
	for _, tc := range []string{"stale", "revoked", "revision"} {
		r := rev
		expected := status.Generation
		p := permit
		if tc == "stale" {
			expected--
		}
		if tc == "revoked" {
			p = func() bool { return false }
		}
		if tc == "revision" {
			r[0] ^= 1
		}
		s, e := InventoryHistoryArchive(path, key, id, r, expected, p)
		after, _ := readInventory(store)
		if e == nil || s != (inventorystore.HistoryArchiveStatus{}) || !bytes.Equal(image, after) {
			t.Fatal("refused archive changed image", tc, e)
		}
	}
	saved, err := InventoryHistoryArchive(path, key, id, rev, status.Generation, permit)
	if err != nil || saved.Active != 1 || saved.Archived != 512 {
		t.Fatal("archive refused", err)
	}
	if _, err := InventoryHistoryArchive(path, key, id, rev, status.Generation, permit); !errors.Is(err, inventorystore.ErrStaleGeneration) {
		t.Fatal("archive replay admitted")
	}
	backup := filepath.Join(privateSnapshotDir(t), "history.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); err != nil {
		t.Fatal(err)
	}
	k, install, err := OpenWithIdentity(fresh, password)
	defer clear(k)
	if err != nil {
		t.Fatal(err)
	}
	revision, _ := Revision(fresh)
	restored, g, err := ReadInventoryHistory(fresh, k, install, revision)
	if err != nil || g != saved.Generation || len(restored) != 513 || !reflect.DeepEqual(before, restored[:512]) || restored[512].Action != "history-archived" {
		t.Fatal("full recovery lost archive", err)
	}
	if info, err := os.Stat(filepath.Join(filepath.Dir(fresh), inventoryName)); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe restored archive permissions")
	}
}
