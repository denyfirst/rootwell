//go:build linux

package instanceaccess

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxAccessWriterLockRejectsConcurrentPasswordChange(t *testing.T) {
	path := accessPath(t)
	const initial = "a sufficiently long initial password"
	const next = "a sufficiently long changed password"
	if err := Create(path, initial); err != nil {
		t.Fatal(err)
	}
	if err := withAccessWriteLock(path, func() error {
		if err := ChangeInitialPassword(path, initial, next); !errors.Is(err, ErrAccessBusy) {
			t.Fatalf("concurrent change was not rejected: %v", err)
		}
		if _, err := Open(path, initial); !errors.Is(err, ErrChangeRequired) {
			t.Fatalf("busy writer changed access: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := ChangeInitialPassword(path, initial, next); err != nil {
		t.Fatalf("released lock prevented change: %v", err)
	}
	if key, err := Open(path, next); err != nil || len(key) != 32 {
		t.Fatalf("serialized change failed: %v", err)
	}
	info, err := os.Lstat(filepath.Join(filepath.Dir(path), accessLockName))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock file missing or unsafe: %v", err)
	}
}

func TestLinuxAccessWriterRefusesUnsafeDirectoryAndLock(t *testing.T) {
	const initial = "a sufficiently long initial password"
	const next = "a sufficiently long changed password"
	path := accessPath(t)
	if err := Create(path, initial); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ChangeInitialPassword(path, initial, next); !errors.Is(err, ErrUnsafeAccessStore) {
		t.Fatalf("permissive data directory accepted: %v", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(filepath.Dir(path), accessLockName)
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ChangeInitialPassword(path, initial, next); !errors.Is(err, ErrUnsafeAccessStore) {
		t.Fatalf("permissive lock file accepted: %v", err)
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, lockPath); err != nil {
		t.Fatal(err)
	}
	if err := ChangeInitialPassword(path, initial, next); !errors.Is(err, ErrUnsafeAccessStore) {
		t.Fatalf("symlink lock accepted: %v", err)
	}
	if _, err := Open(path, initial); !errors.Is(err, ErrChangeRequired) {
		t.Fatalf("unsafe lock changed access: %v", err)
	}
}
