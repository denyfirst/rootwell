//go:build linux

package instanceaccess

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxAutomationStatusReadOnlyRevisionAndFullRestore(t *testing.T) {
	path, code, key, id, fp, rev := completedFixtureStore(t, true)
	defer clear(key)
	at := time.Now().UTC().Add(time.Second)
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ReadAutomationStatus(path, key, id, rev, at)
	if err != nil || s.Generation != 23 || len(s.Certificates) != 2 {
		t.Fatal("legitimate overview refused", err)
	}
	found := false
	for _, r := range s.Certificates {
		if r.Fingerprint == fp {
			found = true
			if r.State != "superseded" {
				t.Fatal("retained source selected again")
			}
		}
	}
	if !found {
		t.Fatal("retained original missing")
	}
	after, err := readInventory(store)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("overview changed image")
	}
	if bad, err := ReadAutomationStatus(path, key, id, [32]byte{}, at); err == nil || bad.Generation != 0 || bad.Certificates != nil {
		t.Fatal("stale revision exposed status")
	}
	backup := filepath.Join(privateSnapshotDir(t), "automation.rwfull")
	if err := ExportFullSnapshot(path, backup, closedGateTestPassword, code); err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(s)
	for _, method := range []SnapshotUnlock{SnapshotPassword, SnapshotRecoveryCode} {
		fresh := filepath.Join(privateSnapshotDir(t), "access.json")
		credential := closedGateTestPassword
		if method == SnapshotRecoveryCode {
			credential = code
		}
		if err := RestoreFullSnapshot(backup, fresh, credential, method); err != nil {
			t.Fatal(err)
		}
		rk, ri, err := OpenWithIdentity(fresh, closedGateTestPassword)
		if err != nil {
			t.Fatal(err)
		}
		rrev, err := Revision(fresh)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ReadAutomationStatus(fresh, rk, ri, rrev, at)
		clear(rk)
		encoded, _ := json.Marshal(r)
		if err != nil || !bytes.Equal(public, encoded) {
			t.Fatal("full restore changed overview", err)
		}
	}
	if err := os.Chmod(store, 0o644); err != nil {
		t.Fatal(err)
	}
	if bad, err := ReadAutomationStatus(path, key, id, rev, at); err == nil || bad.Generation != 0 {
		t.Fatal("unsafe permissions exposed status")
	}
}
