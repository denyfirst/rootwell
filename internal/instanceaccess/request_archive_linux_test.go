//go:build linux

package instanceaccess

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func requestArchiveStore(t *testing.T) (string, string, string, []byte, []byte, [32]byte) {
	t.Helper()
	path, password, code, key, id, rev := readyOrderStore(t)
	image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(image)
	dir := privateSnapshotDir(t)
	input := filepath.Join(dir, "synthetic-request-archive-input.json")
	body, err := json.Marshal(struct{ Key, ID, Image []byte }{key, id, image})
	defer clear(body)
	if err != nil || os.WriteFile(input, body, 0600) != nil {
		t.Fatal("private fixture input")
	}
	command := exec.Command("go", "test", "../inventorystore", "-run=^TestGenerateRequestArchiveFixture$", "-count=1")
	command.Env = append(os.Environ(), "ROOTWELL_REQUEST_ARCHIVE_FIXTURE="+input)
	if command.Run() != nil {
		t.Fatal("private request fixture failed")
	}
	filled, err := os.ReadFile(filepath.Join(dir, "synthetic-request-archive-output.json"))
	defer clear(filled)
	if err != nil {
		t.Fatal(err)
	}
	if err := replaceInventory(filepath.Join(filepath.Dir(path), inventoryName), filled); err != nil {
		t.Fatal(err)
	}
	return path, password, code, key, id, rev
}

func TestLinuxRequestArchiveWriterFullRecoveryAndLostResult(t *testing.T) {
	path, password, code, key, id, rev := requestArchiveStore(t)
	defer clear(key)
	permit := func() bool { return true }
	status, err := InventoryRequestArchive(path, key, id, rev, 0, permit)
	if err != nil || !status.CanArchive || status.Active != 16 {
		t.Fatal("valid status refused", err)
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, _ := readInventory(store)
	for _, tc := range []string{"stale", "revision", "revoked", "revoked-before-commit"} {
		r, g, p := rev, status.Generation, permit
		switch tc {
		case "stale":
			g--
		case "revision":
			r[0] ^= 1
		case "revoked":
			p = func() bool { return false }
		case "revoked-before-commit":
			calls := 0
			p = func() bool { calls++; return calls < 2 }
		}
		out, e := InventoryRequestArchive(path, key, id, r, g, p)
		after, _ := readInventory(store)
		if e == nil || out != (inventorystore.RequestArchiveStatus{}) || !bytes.Equal(before, after) {
			t.Fatal("refused repack changed storage", tc, e)
		}
	}
	if err := withAccessWriteLock(path, func() error {
		if _, err := InventoryRequestArchive(path, key, id, rev, status.Generation, permit); !errors.Is(err, ErrAccessBusy) {
			t.Fatal("archive lost exclusive writer", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if out, err := InventoryRequestArchive(path, key, id, rev, status.Generation, func() bool { calls++; return calls < 3 }); !errors.Is(err, ErrInventoryUncertain) || out != (inventorystore.RequestArchiveStatus{}) {
		t.Fatal("lost result claimed success", err)
	}
	saved, err := InventoryRequestArchive(path, key, id, rev, 0, permit)
	if err != nil || saved.Active != 0 || saved.Archived != 16 || saved.Generation != status.Generation+1 {
		t.Fatal("lost result not recoverable by status", err)
	}
	if _, err := InventoryRequestArchive(path, key, id, rev, status.Generation, permit); !errors.Is(err, inventorystore.ErrStaleGeneration) {
		t.Fatal("old archive authority replayed")
	}
	backup := filepath.Join(privateSnapshotDir(t), "request-history.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	for _, method := range []SnapshotUnlock{SnapshotPassword, SnapshotRecoveryCode} {
		credential := password
		if method == SnapshotRecoveryCode {
			credential = code
		}
		fresh := filepath.Join(privateSnapshotDir(t), "access.json")
		if err := RestoreFullSnapshot(backup, fresh, credential, method); err != nil {
			t.Fatal(err)
		}
		k, install, err := OpenWithIdentity(fresh, password)
		if err != nil {
			t.Fatal(err)
		}
		r, err := Revision(fresh)
		if err != nil {
			clear(k)
			t.Fatal(err)
		}
		out, err := InventoryRequestArchive(fresh, k, install, r, 0, permit)
		clear(k)
		if err != nil || out != saved {
			t.Fatal("full restore lost retained pages", err)
		}
		if info, err := os.Stat(filepath.Join(filepath.Dir(fresh), inventoryName)); err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe restored store")
		}
	}
}

func TestGenerateRequestArchiveGateFixture(t *testing.T) {
	destination := os.Getenv("ROOTWELL_REQUEST_ARCHIVE_GATE_FIXTURE")
	if destination == "" {
		t.Skip("private fixture not requested")
	}
	if !filepath.IsAbs(destination) || filepath.Base(destination) != "synthetic-request-archive-gate.json" {
		t.Fatal("fixture destination refused")
	}
	path, _, _, key, _, _ := requestArchiveStore(t)
	defer clear(key)
	access, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(access)
	image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(image)
	body, err := json.Marshal(struct{ Access, Image []byte }{access, image})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		t.Fatal(err)
	}
}
