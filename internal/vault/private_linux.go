//go:build linux

package vault

import (
	"os"
	"path/filepath"
	"syscall"
)

// privateDirectory accepts only a real 0700 directory owned by the service's
// user. When file is named, it must be absent or a 0600 regular file of the
// same owner.
func privateDirectory(path, file string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || !ownedByService(info) {
		return ErrRefused
	}
	if file == "" {
		return nil
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return ErrRefused
	}
	defer root.Close()
	entry, err := root.Lstat(file)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !entry.Mode().IsRegular() || entry.Mode().Perm() != 0o600 || !ownedByService(entry) {
		return ErrRefused
	}
	return nil
}

// openKeyFile opens the key file without following a link, and checks what
// was opened, not the name: a 0600 regular file of the service's user, in a
// 0700 directory of the same user.
func openKeyFile(path string) (*os.File, error) {
	if privateDirectory(filepath.Dir(path), "") != nil {
		return nil, ErrRefused
	}
	// #nosec G304 -- the path is the operator's own key file location, never request input.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrRefused
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ownedByService(info) {
		_ = f.Close()
		return nil, ErrRefused
	}
	return f, nil
}

func ownedByService(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(os.Geteuid())
}

func syncDirectory(path string) error {
	// #nosec G304 -- the directory is the operator's own key or data location.
	d, err := os.Open(path)
	if err != nil {
		return ErrRefused
	}
	defer d.Close()
	if d.Sync() != nil {
		return ErrRefused
	}
	return nil
}
