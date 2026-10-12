//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func TestLinuxCompletionRefusesUntrustedReceiptRevisionPermissionAndStaleGeneration(t *testing.T) {
	path, _, _, key, id, revision := readyIssuanceStore(t)
	defer clear(key)
	_, _, err := RunStagingIssuance(path, key, id, revision, 11, false, func() bool { return true }, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (string, error) {
		return "processing", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		rev    [32]byte
		gen    uint64
		permit func() bool
	}{{revision, 13, nil}, {revision, 13, func() bool { return false }}, {[32]byte{}, 13, func() bool { return true }}, {revision, 12, func() bool { return true }}, {revision, 13, func() bool { return true }}} {
		s, g, err := CompleteStagingIssuance(path, key, id, tc.rev, tc.gen, [][]byte{[]byte("untrusted malformed certificate")}, tc.permit)
		if err == nil || s.State != "" || g != 0 {
			t.Fatal("untrusted/stale/revoked completion published")
		}
		after, err := readInventory(store)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refused completion changed durable state")
		}
	}
	if err := withAccessWriteLock(path, func() error {
		if _, _, err := CompleteStagingIssuance(path, key, id, revision, 13, nil, func() bool { return true }); err == nil {
			t.Fatal("completion entered second writer")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxCompletedSyntheticPairFullRestorePasswordRecoveryAndDeletion(t *testing.T) {
	// Generate only at runtime using the inventorystore's UNEXPORTED synthetic
	// acceptance seam. No production trust override exists; no secrets are logged
	// or stored in source/CI artifacts. This verifies custody, NOT live CA trust.
	dir := privateSnapshotDir(t)
	fixturePath := filepath.Join(dir, "synthetic-completion.json")
	command := exec.Command("go", "test", "../inventorystore", "-run=^TestGenerateSyntheticCompletionForIntegration$", "-count=1")
	command.Env = append(os.Environ(), "ROOTWELL_TEST_COMPLETION_FIXTURE="+fixturePath)
	if err := command.Run(); err != nil {
		t.Fatal("synthetic completion fixture generation failed")
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
		t.Fatal("fixture invalid")
	}
	defer clear(f.Key)
	const password = "synthetic completed pair restore password"
	wrap, code, err := CreateRecoveryWrap(f.ID, f.Key)
	if err != nil {
		t.Fatal(err)
	}
	access, err := sealWithRecovery(f.Key, password, ready, f.ID, wrap)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := os.WriteFile(path, access, 0o600); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	empty, err := inventorystore.Create(f.Key, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := createInventory(store, empty); err != nil {
		t.Fatal(err)
	}
	if err := withAccessWriteLock(path, func() error { return replaceInventory(store, f.Image) }); err != nil {
		t.Fatal(err)
	}
	rev, err := Revision(path)
	if err != nil {
		t.Fatal(err)
	}
	records, g, err := ReadInventory(path, f.Key, f.ID, rev)
	if err != nil || g != 13 || len(records) != 1 || records[0].StagingOrigin == nil || !records[0].HasPrivateKey {
		t.Fatal("complete fixture publication failed")
	}
	origin := *records[0].StagingOrigin
	var keyHash [32]byte
	if err := WithCertificate(path, f.Key, f.ID, rev, 13, f.Fingerprint, func(_ publicinventory.Record, private []byte) error { keyHash = sha256.Sum256(private); return nil }); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(privateSnapshotDir(t), "completed.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	for _, method := range []SnapshotUnlock{SnapshotPassword, SnapshotRecoveryCode} {
		fresh := filepath.Join(privateSnapshotDir(t), "access.json")
		credential := password
		if method == SnapshotRecoveryCode {
			credential = code
		}
		if err := RestoreFullSnapshot(backup, fresh, credential, method); err != nil {
			t.Fatal(err)
		}
		const recovered = "synthetic recovered completed pair password"
		if _, err := RecoverPassword(fresh, code, recovered); err != nil {
			t.Fatal(err)
		}
		key, id, err := OpenWithIdentity(fresh, recovered)
		if err != nil {
			t.Fatal(err)
		}
		revision, err := Revision(fresh)
		if err != nil {
			t.Fatal(err)
		}
		r, g, err := ReadInventory(fresh, key, id, revision)
		if err != nil || g != 13 || len(r) != 1 || !reflect.DeepEqual(r[0].StagingOrigin, &origin) || r[0].KeyStatus != "matched" {
			t.Fatal("complete restore lost origin/pair")
		}
		if err := WithCertificate(fresh, key, id, revision, 13, f.Fingerprint, func(_ publicinventory.Record, private []byte) error {
			if sha256.Sum256(private) != keyHash {
				t.Fatal("restored private key changed")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		called := false
		if _, _, err := RunStagingIssuance(fresh, key, id, revision, 13, true, func() bool { return true }, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (string, error) {
			called = true
			return "processing", nil
		}); err == nil || called {
			t.Fatal("complete restore recreated network authority")
		}
		clear(key)
		if st, err := os.Stat(filepath.Join(filepath.Dir(fresh), inventoryName)); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatal("restored completed key permissions unsafe")
		}
	}
	if g, err := DeleteInventoryRecord(path, f.Key, f.ID, rev, 13, f.Fingerprint); err != nil || g != 14 {
		t.Fatal("completed durable pair deletion failed")
	}
	r, g, err := ReadInventory(path, f.Key, f.ID, rev)
	if err != nil || g != 14 || len(r) != 0 {
		t.Fatal("deletion retained current pair")
	}
	s, g, err := ReadStagingIssuance(path, f.Key, f.ID, rev)
	if err != nil || g != 14 || s.State != "saved-certificate-deleted" {
		t.Fatal("deletion lost no-replay tombstone")
	}
}
