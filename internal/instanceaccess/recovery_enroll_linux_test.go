//go:build linux

package instanceaccess

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxRecoveryCeremonySerializesAndPreservesDataKey(t *testing.T) {
	path, password, key, id := readyV2Fixture(t)
	if err := withAccessWriteLock(path, func() error {
		if code, err := EnrollRecovery(path, password); code != "" || !errors.Is(err, ErrAccessBusy) {
			t.Fatalf("busy writer enrolled recovery: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	code, err := EnrollRecovery(path, password)
	if err != nil || len(code) != 64 {
		t.Fatalf("enrollment failed: %v", err)
	}
	const next = "a sufficiently long replacement password"
	newCode, err := RecoverPassword(path, code, next)
	if err != nil || len(newCode) != 64 || newCode == code {
		t.Fatalf("recovery failed: %v", err)
	}
	opened, openedID, err := OpenWithIdentity(path, next)
	if err != nil || !bytes.Equal(opened, key) || !bytes.Equal(openedID, id) {
		t.Fatalf("recovery changed key or identity: %v", err)
	}
	clear(opened)
	if _, err := RecoverPassword(path, code, "another sufficiently long password"); !errors.Is(err, ErrInvalidRecovery) {
		t.Fatalf("reused code accepted: %v", err)
	}
}

func TestLinuxRecoveryRefusesUnsafeStore(t *testing.T) {
	path, password, _, _ := readyV2Fixture(t)
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if code, err := EnrollRecovery(path, password); code != "" || !errors.Is(err, ErrUnsafeAccessStore) {
		t.Fatalf("permissive directory enrolled recovery: %v", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenWithIdentity(path, password); err != nil {
		t.Fatalf("refusal damaged installation: %v", err)
	}
}
