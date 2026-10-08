//go:build linux

package instanceaccess

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

// TestContainerVolumeDrill runs in separate, disposable containers with four
// distinct bind mounts. It never uses a real installation or a real secret.
// No credential crosses a container boundary through argv or environment.
func TestContainerVolumeDrill(t *testing.T) {
	phase := os.Getenv("ROOTWELL_VOLUME_DRILL_PHASE")
	if phase == "" {
		t.Skip("run by the container volume drill")
	}
	const password = "test-only disposable container volume password"
	data := filepath.Join("/data", "access.json")
	backup := filepath.Join("/backup", "after-import.rwfull")
	for _, pair := range [][2]string{{"/data", "/backup"}, {"/data", "/fresh"}, {"/backup", "/recovery"}} {
		left, leftErr := os.Stat(pair[0])
		right, rightErr := os.Stat(pair[1])
		if leftErr != nil || rightErr != nil || os.SameFile(left, right) {
			t.Fatal("volume mounts must be present and distinct")
		}
	}
	switch phase {
	case "seed":
		const initial = "test-only disposable initial password"
		if err := Create(data, initial); err != nil {
			t.Fatal(err)
		}
		if err := ChangeInitialPassword(data, initial, password); err != nil {
			t.Fatal(err)
		}
		code, err := EnrollRecovery(data, password)
		if err != nil {
			t.Fatal(err)
		}
		writeDrillCode(t, code)
		initialBackup := filepath.Join("/backup", "initial.rwfull")
		if err := InitializeInventory(data, initialBackup, password, code); err != nil {
			t.Fatal(err)
		}
		key, id, err := OpenWithIdentity(data, password)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(key)
		revision, err := Revision(data)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := os.ReadFile("/demo.pem")
		if err != nil {
			t.Fatal(err)
		}
		added, generation, err := AppendInventory(data, key, id, revision, cert, "Operations", "test/nginx")
		if err != nil || len(added) != 1 || generation != 2 {
			t.Fatalf("volume import failed: %v", err)
		}
		if record, generation, err := AssociateInventoryLocation(data, key, id, revision, 2, added[0].Fingerprint, "test/haproxy"); err != nil || generation != 3 || len(record.Locations) != 2 {
			t.Fatalf("volume association failed: %v", err)
		}
		if record, generation, err := UpdateInventoryOwner(data, key, id, revision, 3, added[0].Fingerprint, "Security"); err != nil || generation != 4 || record.Owner != "Security" || len(record.Locations) != 2 {
			t.Fatalf("volume owner correction failed: %v", err)
		}
		if record, generation, err := ChangeInventoryLocation(data, key, id, revision, 4, added[0].Fingerprint, "test/nginx", "test/primary", inventorystore.LocationRename); err != nil || generation != 5 || record.Location != "test/primary" {
			t.Fatalf("volume location correction failed: %v", err)
		}
		if status, generation, err := PrepareStagingAccount(data, key, id, revision, 5, func() bool { return true }); err != nil || generation != 6 || status.State != "key-prepared" {
			t.Fatal("container account preparation failed")
		}
		if err := ExportFullSnapshot(data, backup, password, code); err != nil {
			t.Fatal(err)
		}
		checkDrillState(t, data, backup, password, code)
	case "reopen":
		code := readDrillCode(t)
		checkDrillState(t, data, backup, password, code)
		release, err := AcquireOperationLock(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := ExportFullSnapshot(data, filepath.Join("/backup", "must-not-exist.rwfull"), password, code); !errors.Is(err, ErrOperationBusy) {
			t.Fatalf("live-volume export was not refused: %v", err)
		}
		release()
		if _, err := os.Stat(filepath.Join("/backup", "must-not-exist.rwfull")); !os.IsNotExist(err) {
			t.Fatal("busy export created a backup")
		}
	case "busy":
		if err := ExportFullSnapshot(data, filepath.Join("/backup", "while-serving.rwfull"), password, readDrillCode(t)); !errors.Is(err, ErrOperationBusy) {
			t.Fatalf("serving volume allowed an offline backup: %v", err)
		}
		if _, err := os.Stat(filepath.Join("/backup", "while-serving.rwfull")); !os.IsNotExist(err) {
			t.Fatal("serving-volume refusal wrote a backup")
		}
	case "restore":
		code := readDrillCode(t)
		tampered := filepath.Join("/backup", "tampered.rwfull")
		body, err := os.ReadFile(backup)
		if err != nil {
			t.Fatal(err)
		}
		body[len(body)-1] ^= 1
		if err := os.WriteFile(tampered, body, 0o600); err != nil {
			t.Fatal(err)
		}
		fresh := filepath.Join("/fresh", "access.json")
		if err := RestoreFullSnapshot(tampered, fresh, code, SnapshotRecoveryCode); !errors.Is(err, ErrInvalidFullSnapshot) {
			t.Fatalf("tampered volume backup was accepted: %v", err)
		}
		if err := RestoreFullSnapshot(backup, fresh, "wrong recovery code", SnapshotRecoveryCode); !errors.Is(err, ErrInvalidFullSnapshot) {
			t.Fatalf("wrong recovery code was accepted: %v", err)
		}
		if entries, err := os.ReadDir("/fresh"); err != nil || len(entries) != 0 {
			t.Fatal("rejected restore modified fresh volume")
		}
		if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); err != nil {
			t.Fatal(err)
		}
		checkDrillState(t, fresh, backup, password, code)
		if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); !errors.Is(err, ErrSnapshotNotEmpty) {
			t.Fatalf("restore overwrote a nonempty volume: %v", err)
		}
	case "unsafe":
		release, err := AcquireOperationLock(data)
		if release != nil {
			release()
		}
		if !errors.Is(err, ErrUnsafeAccessStore) {
			t.Fatalf("permissive volume locked: %v", err)
		}
		if err := ExportFullSnapshot(data, filepath.Join("/backup", "unsafe.rwfull"), password, readDrillCode(t)); !errors.Is(err, ErrUnsafeAccessStore) {
			t.Fatalf("permissive volume exported: %v", err)
		}
	default:
		t.Fatal("unknown volume drill phase")
	}
}

func checkDrillState(t *testing.T, accessPath, backupPath, password, code string) {
	t.Helper()
	for _, path := range []string{accessPath, filepath.Join(filepath.Dir(accessPath), inventoryName), backupPath} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("volume file is not private: %v", err)
		}
	}
	key, id, err := OpenWithIdentity(accessPath, password)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	revision, err := Revision(accessPath)
	if err != nil {
		t.Fatal(err)
	}
	records, generation, err := ReadInventory(accessPath, key, id, revision)
	if err != nil || generation != 6 || len(records) != 1 || records[0].Owner != "Security" || records[0].Location != "test/primary" ||
		len(records[0].Locations) != 2 || records[0].Locations[1] != "test/haproxy" || records[0].ImportGeneration != 2 {
		t.Fatalf("volume inventory did not survive: %v", err)
	}
	if ids, snapshotGeneration, err := VerifyFullSnapshot(backupPath, code, SnapshotRecoveryCode); err != nil || snapshotGeneration != generation || !bytes.Equal(ids, id) {
		t.Fatalf("volume backup did not authenticate: %v", err)
	}
	account, accountGen, err := ReadStagingAccount(accessPath, key, id, revision)
	if err != nil || accountGen != generation || account.State != "key-prepared" {
		t.Fatal("container restart/restore lost account key")
	}
	snapshot, err := readFullSnapshot(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _, image, _, err := openFullSnapshot(snapshot, code, SnapshotRecoveryCode)
	if err != nil {
		t.Fatal(err)
	}
	backedUp, _, err := inventorystore.ReadStagingAccount(key, id, image)
	if err != nil || backedUp != account {
		t.Fatal("container restored a different account key")
	}
	if _, _, err := AppendInventory(accessPath, key, id, revision, mustReadDrillCertificate(t), "", ""); !errors.Is(err, publicinventory.ErrDuplicate) {
		t.Fatalf("restored duplicate was not refused: %v", err)
	}
}

func mustReadDrillCertificate(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile("/demo.pem")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func writeDrillCode(t *testing.T, code string) {
	t.Helper()
	f, err := os.OpenFile("/recovery/code", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(code); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func readDrillCode(t *testing.T) string {
	t.Helper()
	info, err := os.Lstat("/recovery/code")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("test recovery code file is missing or unsafe")
	}
	body, err := os.ReadFile("/recovery/code")
	if err != nil || len(body) != 64 {
		t.Fatal("test recovery code could not be read")
	}
	return string(body)
}
