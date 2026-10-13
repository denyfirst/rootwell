//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

const closedGateTestPassword = "a different long test password"

func completedClosureStore(t *testing.T) (path, code string, key, id []byte, fp string, revision [32]byte) {
	t.Helper()
	fixturePath := filepath.Join(privateSnapshotDir(t), "synthetic-completion.json")
	command := exec.Command("go", "test", "../inventorystore", "-run=^TestGenerateSyntheticCompletionForIntegration$", "-count=1")
	command.Env = append(os.Environ(), "ROOTWELL_TEST_COMPLETION_FIXTURE="+fixturePath)
	if err := command.Run(); err != nil {
		t.Fatal("synthetic completion fixture failed")
	}
	body, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	var f struct {
		Key, ID, Image []byte
		Fingerprint    string
	}
	if json.Unmarshal(body, &f) != nil {
		t.Fatal("invalid private fixture")
	}
	key, id, fp = f.Key, f.ID, f.Fingerprint
	wrap, code, err := CreateRecoveryWrap(id, key)
	if err != nil {
		t.Fatal(err)
	}
	access, err := sealWithRecovery(key, closedGateTestPassword, ready, id, wrap)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(privateSnapshotDir(t), "access.json")
	if err := os.WriteFile(path, access, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createInventory(filepath.Join(filepath.Dir(path), inventoryName), f.Image); err != nil {
		t.Fatal(err)
	}
	revision, err = Revision(path)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestLinuxNewRequestAtomicRevisionPermissionFullRestoreAndPairDeletion(t *testing.T) {
	path, code, key, id, fp, rev := completedClosureStore(t)
	defer clear(key)
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	allow := func() bool { return true }
	for _, tc := range []struct {
		rev    [32]byte
		gen    uint64
		permit func() bool
	}{{rev, 12, allow}, {[32]byte{}, 13, allow}, {rev, 13, nil}, {rev, 13, func() bool { return false }}} {
		if s, g, err := CloseStagingRequest(path, key, id, tc.rev, tc.gen, tc.permit); err == nil || s.Reason != "" || g != 0 {
			t.Fatal("stale or revoked closure succeeded")
		}
		after, err := readInventory(store)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refused closure mutated image")
		}
	}
	if err := withAccessWriteLock(path, func() error {
		if _, _, err := CloseStagingRequest(path, key, id, rev, 13, allow); err == nil {
			t.Fatal("second writer entered closure")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	permitted := true
	checks := 0
	if _, _, err := CloseStagingRequest(path, key, id, rev, 13, func() bool {
		checks++
		if checks >= 2 {
			permitted = false
		}
		return permitted
	}); err == nil {
		t.Fatal("late revoked close published")
	}
	after, _ := readInventory(store)
	if !bytes.Equal(before, after) {
		t.Fatal("revoked closure lost current request")
	}
	var originalHash [32]byte
	if err := WithCertificate(path, key, id, rev, 13, fp, func(_ publicinventory.Record, private []byte) error {
		originalHash = sha256.Sum256(private)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, g, err := CloseStagingRequest(path, key, id, rev, 13, allow)
	if err != nil || g != 14 || s.Reason != "not-started" || s.ClosedCount != 1 {
		t.Fatal("valid local closure refused")
	}
	if _, _, err := CloseStagingRequest(path, key, id, rev, 14, allow); err == nil {
		t.Fatal("closed scope reopened")
	}
	backup := filepath.Join(privateSnapshotDir(t), "closed.rwfull")
	if err := ExportFullSnapshot(path, backup, closedGateTestPassword, code); err != nil {
		t.Fatal(err)
	}
	for _, method := range []SnapshotUnlock{SnapshotPassword, SnapshotRecoveryCode} {
		fresh := filepath.Join(privateSnapshotDir(t), "access.json")
		credential := closedGateTestPassword
		if method == SnapshotRecoveryCode {
			credential = code
		}
		if err := RestoreFullSnapshot(backup, fresh, credential, method); err != nil {
			t.Fatal(err)
		}
		const recovered = "closed request recovered test password"
		if _, err := RecoverPassword(fresh, code, recovered); err != nil {
			t.Fatal(err)
		}
		rk, ri, err := OpenWithIdentity(fresh, recovered)
		if err != nil {
			t.Fatal(err)
		}
		rrev, err := Revision(fresh)
		if err != nil {
			t.Fatal(err)
		}
		s, g, err := ReadNewStagingRequest(fresh, rk, ri, rrev)
		if err != nil || g != 14 || s.ClosedCount != 1 || s.Reason != "not-started" {
			t.Fatal("full restore lost closed scope")
		}
		if err := WithCertificate(fresh, rk, ri, rrev, 14, fp, func(r publicinventory.Record, private []byte) error {
			if sha256.Sum256(private) != originalHash || r.StagingOrigin == nil || r.KeyStatus != "matched" {
				t.Fatal("restored prior pair/provenance differs")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if g, err := DeleteInventoryRecord(fresh, rk, ri, rrev, 14, fp); err != nil || g != 15 {
			t.Fatal("restored archived pair deletion refused")
		}
		if records, g, err := ReadInventory(fresh, rk, ri, rrev); err != nil || g != 15 || len(records) != 0 {
			t.Fatal("archived deletion retained pair")
		}
		if s, g, err := ReadNewStagingRequest(fresh, rk, ri, rrev); err != nil || g != 15 || s.ClosedCount != 1 {
			t.Fatal("delete lost closed tombstone")
		}
		clear(rk)
		if st, err := os.Stat(filepath.Join(filepath.Dir(fresh), inventoryName)); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatal("restored archive permissions unsafe")
		}
	}
	// Actual earlier encrypted image stays unchanged and can still be read.
	if records, g, err := inventorystore.Open(key, id, before); err != nil || g != 13 || len(records) != 1 {
		t.Fatal("closure changed old snapshot")
	}
}

// Private runtime-only child fixture for real HTTP gate tests; no raw data key
// leaves this helper, only encrypted access/image and a public fingerprint.
func TestGenerateClosedRequestGateFixture(t *testing.T) {
	destination := os.Getenv("ROOTWELL_CLOSED_GATE_FIXTURE")
	if destination == "" {
		t.Skip("private gate fixture not requested")
	}
	if !filepath.IsAbs(destination) || filepath.Base(destination) != "synthetic-closed-gate.json" {
		t.Fatal("fixture destination refused")
	}
	path, _, key, _, fp, _ := completedClosureStore(t)
	defer clear(key)
	access, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(struct {
		Access, Image []byte
		Fingerprint   string
	}{access, image, fp})
	defer clear(body)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal("fixture write refused")
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		t.Fatal("fixture write failed")
	}
}
