//go:build linux

package instanceaccess

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const accessLockName = ".rootwell-access.lock"

// withAccessWriteLock serializes cooperating Linux writers on a stable lock
// inode. The private directory and lock file are never removed automatically.
// Advisory locks do not constrain processes that ignore this protocol.
func withAccessWriteLock(path string, fn func() error) error {
	dir := filepath.Dir(path)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("%w: directory open", ErrUnsafeAccessStore)
	}
	defer root.Close()
	listed, err := os.Lstat(dir)
	if err != nil || !listed.IsDir() || listed.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: directory mode", ErrUnsafeAccessStore)
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(listed, opened) {
		return fmt.Errorf("%w: directory identity", ErrUnsafeAccessStore)
	}
	owner, ok := listed.Sys().(*syscall.Stat_t)
	if !ok || int64(owner.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("%w: directory owner", ErrUnsafeAccessStore)
	}
	lock, err := root.OpenFile(accessLockName, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("%w: lock open", ErrUnsafeAccessStore)
	}
	defer lock.Close()
	lockListed, err := root.Lstat(accessLockName)
	if err != nil || !lockListed.Mode().IsRegular() || lockListed.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: lock mode", ErrUnsafeAccessStore)
	}
	lockOpened, err := lock.Stat()
	if err != nil || !os.SameFile(lockListed, lockOpened) {
		return fmt.Errorf("%w: lock identity", ErrUnsafeAccessStore)
	}
	lockOwner, ok := lockListed.Sys().(*syscall.Stat_t)
	if !ok || int64(lockOwner.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("%w: lock owner", ErrUnsafeAccessStore)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return ErrAccessBusy
		}
		return fmt.Errorf("%w: lock operation", ErrUnsafeAccessStore)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

func syncAccessDirectory(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
