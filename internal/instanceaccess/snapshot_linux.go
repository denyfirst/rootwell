//go:build linux

package instanceaccess

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// ExportAccessSnapshot writes an access-only snapshot to a new file in a
// separate owner-private directory. It does not include inventory records and
// is not a full disaster-recovery backup. Both the current password and the
// separately kept recovery code must be proven; neither is serialized.
func ExportAccessSnapshot(accessPath, snapshotPath, password, code string) error {
	return exportAccessSnapshotWithSync(accessPath, snapshotPath, password, code, syncAccessDirectory)
}

func exportAccessSnapshotWithSync(accessPath, snapshotPath, password, code string, syncDir func(string) error) error {
	if sameDirectory(accessPath, snapshotPath) {
		return ErrUnsafeAccessStore
	}
	releaseOperation, err := AcquireOperationLock(accessPath)
	if err != nil {
		return err
	}
	defer releaseOperation()
	var snapshot []byte
	if err := withAccessWriteLock(accessPath, func() error {
		body, err := readAccess(accessPath)
		if err != nil {
			return err
		}
		snapshot, err = createAccessSnapshot(body, password, code)
		return err
	}); err != nil {
		return err
	}
	root, err := openPrivateRoot(filepath.Dir(snapshotPath))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(snapshotPath)
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrSnapshotExists
		}
		return ErrUnsafeAccessStore
	}
	if err := writeAndSyncFile(f, snapshot); err != nil {
		return ErrSnapshotUncertain
	}
	if err := syncDir(snapshotPath); err != nil {
		return ErrSnapshotUncertain
	}
	installed, err := readSnapshot(snapshotPath)
	if err != nil || !bytes.Equal(installed, snapshot) {
		return ErrSnapshotUncertain
	}
	return nil
}

// VerifyAccessSnapshot authenticates a bounded access-only snapshot without
// restoring it. The returned ID is not secret; a failed check returns no ID.
func VerifyAccessSnapshot(snapshotPath, credential string, method SnapshotUnlock) ([]byte, error) {
	snapshot, err := readSnapshot(snapshotPath)
	if err != nil {
		return nil, err
	}
	_, id, err := openAccessSnapshot(snapshot, credential, method)
	return id, err
}

// RestoreAccessSnapshot accepts only a fresh, otherwise empty private Linux
// directory. It never overwrites an installation. A recovery-code restore
// retains the old password until a separate password-reset ceremony runs.
func RestoreAccessSnapshot(snapshotPath, destinationAccessPath, credential string, method SnapshotUnlock) error {
	return restoreAccessSnapshotWithSync(snapshotPath, destinationAccessPath, credential, method, syncAccessDirectory)
}

func restoreAccessSnapshotWithSync(snapshotPath, destinationAccessPath, credential string, method SnapshotUnlock, syncDir func(string) error) error {
	if filepath.Base(destinationAccessPath) != "access.json" || sameDirectory(snapshotPath, destinationAccessPath) {
		return ErrUnsafeAccessStore
	}
	snapshot, err := readSnapshot(snapshotPath)
	if err != nil {
		return err
	}
	body, _, err := openAccessSnapshot(snapshot, credential, method)
	if err != nil {
		return err
	}
	releaseOperation, err := AcquireOperationLock(destinationAccessPath)
	if err != nil {
		return err
	}
	defer releaseOperation()
	return withAccessWriteLock(destinationAccessPath, func() error {
		entries, err := os.ReadDir(filepath.Dir(destinationAccessPath))
		if err != nil {
			return ErrUnsafeAccessStore
		}
		for _, entry := range entries {
			if entry.Name() != accessLockName && entry.Name() != operationLockName {
				return ErrSnapshotNotEmpty
			}
		}
		root, err := openPrivateRoot(filepath.Dir(destinationAccessPath))
		if err != nil {
			return err
		}
		defer root.Close()
		f, err := root.OpenFile("access.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return ErrSnapshotExists
			}
			return ErrUnsafeAccessStore
		}
		if err := writeAndSyncFile(f, body); err != nil {
			return ErrSnapshotUncertain
		}
		if err := syncDir(destinationAccessPath); err != nil {
			return ErrSnapshotUncertain
		}
		installed, err := readAccess(destinationAccessPath)
		if err != nil || !bytes.Equal(installed, body) {
			return ErrSnapshotUncertain
		}
		return nil
	})
}

func sameDirectory(first, second string) bool {
	a, errA := os.Stat(filepath.Dir(first))
	b, errB := os.Stat(filepath.Dir(second))
	return errA == nil && errB == nil && os.SameFile(a, b)
}

func writeAndSyncFile(f *os.File, body []byte) error {
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if n, err := f.Write(body); err != nil || n != len(body) {
		_ = f.Close()
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func readSnapshot(path string) ([]byte, error) {
	root, err := openPrivateRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	listed, err := root.Lstat(name)
	if err != nil || !listed.Mode().IsRegular() || listed.Mode().Perm()&0o077 != 0 {
		return nil, ErrInvalidSnapshot
	}
	owner, ok := listed.Sys().(*syscall.Stat_t)
	if !ok || int64(owner.Uid) != int64(os.Geteuid()) {
		return nil, ErrInvalidSnapshot
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, ErrInvalidSnapshot
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 || !os.SameFile(listed, opened) {
		return nil, ErrInvalidSnapshot
	}
	body, err := io.ReadAll(io.LimitReader(f, int64(maxSnapshotFile+1)))
	if err != nil || len(body) > maxSnapshotFile {
		return nil, ErrInvalidSnapshot
	}
	return body, nil
}
