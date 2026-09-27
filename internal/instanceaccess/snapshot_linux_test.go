//go:build linux

package instanceaccess

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func privateSnapshotDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLinuxAccessSnapshotFreshRestoreDrill(t *testing.T) {
	accessPath, password, key, id := readyV2Fixture(t)
	code, err := EnrollRecovery(accessPath, password)
	if err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(privateSnapshotDir(t), "rootwell-access.rwab")
	if err := ExportAccessSnapshot(accessPath, snapshotPath, password, code); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(snapshotPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot permissions are unsafe: %v", err)
	}
	for _, tc := range []struct {
		credential string
		method     SnapshotUnlock
	}{{password, SnapshotPassword}, {code, SnapshotRecoveryCode}} {
		got, err := VerifyAccessSnapshot(snapshotPath, tc.credential, tc.method)
		if err != nil || !bytes.Equal(got, id) {
			t.Fatalf("snapshot verification failed: %v", err)
		}
	}
	destination := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := RestoreAccessSnapshot(snapshotPath, destination, code, SnapshotRecoveryCode); err != nil {
		t.Fatal(err)
	}
	opened, openedID, err := OpenWithIdentity(destination, password)
	if err != nil || !bytes.Equal(opened, key) || !bytes.Equal(openedID, id) {
		t.Fatalf("restored installation has a different key or ID: %v", err)
	}
	clear(opened)
	const next = "a sufficiently long restored password"
	if _, err := RecoverPassword(destination, code, next); err != nil {
		t.Fatalf("offline code could not reset restored password: %v", err)
	}
	opened, openedID, err = OpenWithIdentity(destination, next)
	if err != nil || !bytes.Equal(opened, key) || !bytes.Equal(openedID, id) {
		t.Fatalf("recovered restore changed key or ID: %v", err)
	}
	clear(opened)
	if err := RestoreAccessSnapshot(snapshotPath, destination, code, SnapshotRecoveryCode); !errors.Is(err, ErrSnapshotNotEmpty) {
		t.Fatalf("restore overwrote existing installation: %v", err)
	}
}

func TestLinuxAccessSnapshotRefusesUnsafePathsAndTampering(t *testing.T) {
	accessPath, password, _, _ := readyV2Fixture(t)
	code, err := EnrollRecovery(accessPath, password)
	if err != nil {
		t.Fatal(err)
	}
	backupDir := privateSnapshotDir(t)
	snapshotPath := filepath.Join(backupDir, "access.rwab")
	if err := ExportAccessSnapshot(accessPath, snapshotPath, "wrong password", code); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password exported snapshot: %v", err)
	}
	if err := ExportAccessSnapshot(accessPath, snapshotPath, password, "wrong-code"); !errors.Is(err, ErrInvalidRecovery) {
		t.Fatalf("wrong recovery code exported snapshot: %v", err)
	}
	if _, err := os.Lstat(snapshotPath); !os.IsNotExist(err) {
		t.Fatalf("rejected export created a file: %v", err)
	}
	if err := os.Chmod(backupDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ExportAccessSnapshot(accessPath, snapshotPath, password, code); !errors.Is(err, ErrUnsafeAccessStore) {
		t.Fatalf("permissive backup directory was accepted: %v", err)
	}
	if err := os.Chmod(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := withAccessWriteLock(accessPath, func() error {
		if err := ExportAccessSnapshot(accessPath, snapshotPath, password, code); !errors.Is(err, ErrAccessBusy) {
			t.Fatalf("backup ignored active writer: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := ExportAccessSnapshot(accessPath, snapshotPath, password, code); err != nil {
		t.Fatal(err)
	}
	if err := ExportAccessSnapshot(accessPath, filepath.Join(filepath.Dir(accessPath), "same-dir.rwab"), password, code); !errors.Is(err, ErrUnsafeAccessStore) {
		t.Fatalf("same-directory backup was accepted: %v", err)
	}
	if err := ExportAccessSnapshot(accessPath, snapshotPath, password, code); !errors.Is(err, ErrSnapshotExists) {
		t.Fatalf("backup overwrote an existing file: %v", err)
	}
	symlinkPath := filepath.Join(backupDir, "symlink.rwab")
	if err := os.Symlink(snapshotPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccessSnapshot(symlinkPath, password, SnapshotPassword); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("symlink snapshot was accepted: %v", err)
	}
	contents, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	contents[len(contents)-1] ^= 1
	if err := os.WriteFile(snapshotPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := RestoreAccessSnapshot(snapshotPath, destination, password, SnapshotPassword); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("tampered snapshot restored: %v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("invalid snapshot created access file: %v", err)
	}
}

func TestLinuxAccessSnapshotPostWriteSyncFailureIsUncertain(t *testing.T) {
	accessPath, password, _, _ := readyV2Fixture(t)
	code, err := EnrollRecovery(accessPath, password)
	if err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(privateSnapshotDir(t), "access.rwab")
	err = exportAccessSnapshotWithSync(accessPath, snapshotPath, password, code, func(string) error {
		return errors.New("simulated backup directory sync fault")
	})
	if !errors.Is(err, ErrSnapshotUncertain) {
		t.Fatalf("post-write backup fault was not uncertain: %v", err)
	}
	if _, err := VerifyAccessSnapshot(snapshotPath, password, SnapshotPassword); err != nil {
		t.Fatalf("uncertain backup was corrupted: %v", err)
	}
	destination := filepath.Join(privateSnapshotDir(t), "access.json")
	err = restoreAccessSnapshotWithSync(snapshotPath, destination, password, SnapshotPassword, func(string) error {
		return errors.New("simulated restore directory sync fault")
	})
	if !errors.Is(err, ErrSnapshotUncertain) {
		t.Fatalf("post-write restore fault was not uncertain: %v", err)
	}
	if _, _, err := OpenWithIdentity(destination, password); err != nil {
		t.Fatalf("uncertain restore was corrupted: %v", err)
	}
}
