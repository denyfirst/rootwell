//go:build linux

package instanceaccess

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxOperationLockExcludesAnotherDaemonOrCeremony(t *testing.T) {
	path, _, _, _ := readyV2Fixture(t)
	release, err := AcquireOperationLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := AcquireOperationLock(path); second != nil || !errors.Is(err, ErrOperationBusy) {
		t.Fatalf("second operation acquired active instance: %v", err)
	}
	release()
	release()
	second, err := AcquireOperationLock(path)
	if err != nil {
		t.Fatalf("released operation remained busy: %v", err)
	}
	second()
}

func TestLinuxOperationLockRefusesUnsafeDirectoryAndLock(t *testing.T) {
	path, _, _, _ := readyV2Fixture(t)
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if release, err := AcquireOperationLock(path); release != nil || !errors.Is(err, ErrUnsafeAccessStore) {
		t.Fatalf("permissive directory accepted: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, operationLockName)
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if release, err := AcquireOperationLock(path); release != nil || !errors.Is(err, ErrUnsafeAccessStore) {
		t.Fatalf("permissive lock accepted: %v", err)
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, lockPath); err != nil {
		t.Fatal(err)
	}
	if release, err := AcquireOperationLock(path); release != nil || !errors.Is(err, ErrUnsafeAccessStore) {
		t.Fatalf("symlink lock accepted: %v", err)
	}
}
