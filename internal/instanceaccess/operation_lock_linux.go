//go:build linux

package instanceaccess

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const operationLockName = ".rootwell-operation.lock"

// AcquireOperationLock excludes a running rootwelld process and an offline
// recovery/backup ceremony from using the same private Linux installation at
// once. It is advisory and requires every cooperating process to participate.
// The persistent lock file must not be unlinked. The returned release is safe
// to call more than once.
func AcquireOperationLock(accessPath string) (func(), error) {
	root, err := openPrivateRoot(filepath.Dir(accessPath))
	if err != nil {
		return nil, err
	}
	lock, err := root.OpenFile(operationLockName, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		root.Close()
		return nil, ErrUnsafeAccessStore
	}
	listed, err := root.Lstat(operationLockName)
	if err != nil || !listed.Mode().IsRegular() || listed.Mode().Perm()&0o077 != 0 {
		lock.Close()
		root.Close()
		return nil, ErrUnsafeAccessStore
	}
	opened, err := lock.Stat()
	if err != nil || !os.SameFile(listed, opened) {
		lock.Close()
		root.Close()
		return nil, ErrUnsafeAccessStore
	}
	owner, ok := listed.Sys().(*syscall.Stat_t)
	if !ok || int64(owner.Uid) != int64(os.Geteuid()) {
		lock.Close()
		root.Close()
		return nil, ErrUnsafeAccessStore
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		root.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrOperationBusy
		}
		return nil, ErrUnsafeAccessStore
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			_ = lock.Close()
			_ = root.Close()
		})
	}, nil
}
