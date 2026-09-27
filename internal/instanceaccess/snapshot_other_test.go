//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"
)

func TestNonLinuxAccessSnapshotFilesystemOperationsFailClosed(t *testing.T) {
	path, password, _, _ := readyV2Fixture(t)
	if err := ExportAccessSnapshot(path, path+".rwab", password, "code"); !errors.Is(err, ErrSnapshotUnsupported) {
		t.Fatalf("non-Linux backup export was enabled: %v", err)
	}
	if id, err := VerifyAccessSnapshot(path, password, SnapshotPassword); id != nil || !errors.Is(err, ErrSnapshotUnsupported) {
		t.Fatalf("non-Linux backup verification was enabled: %v", err)
	}
	if err := RestoreAccessSnapshot(path, path+".restore", password, SnapshotPassword); !errors.Is(err, ErrSnapshotUnsupported) {
		t.Fatalf("non-Linux backup restore was enabled: %v", err)
	}
}
