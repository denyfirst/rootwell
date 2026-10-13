//go:build linux

package instanceaccess

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestLinuxRenewalResultReadOnlyRevisionAndFullRestore(t *testing.T) {
	path, code, key, id, fp, rev := completedFixtureStore(t, true)
	defer clear(key)
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	result, gen, err := ReadStagingRenewalResult(path, key, id, rev, 23)
	if err != nil || result == nil || gen != 23 || result.OriginalFingerprint != fp || !result.ExpiryExtended {
		t.Fatal("completed renewal result refused", err)
	}
	for _, tc := range []struct {
		revision [32]byte
		gen      uint64
	}{{rev, 22}, {[32]byte{}, 23}} {
		if s, g, err := ReadStagingRenewalResult(path, key, id, tc.revision, tc.gen); err == nil || s != nil || g != 0 {
			t.Fatal("stale result exposed partial output")
		}
	}
	after, err := readInventory(store)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("result read mutated custody")
	}
	backup := filepath.Join(privateSnapshotDir(t), "renewal-result.rwfull")
	if err := ExportFullSnapshot(path, backup, closedGateTestPassword, code); err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(result)
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
		r, g, err := ReadStagingRenewalResult(fresh, rk, ri, rrev, 23)
		clear(rk)
		encoded, _ := json.Marshal(r)
		if err != nil || g != 23 || !bytes.Equal(public, encoded) {
			t.Fatal("full restore changed renewal summary")
		}
	}
}
