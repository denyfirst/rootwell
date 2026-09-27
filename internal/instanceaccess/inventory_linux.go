//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

const inventoryName = "inventory.json"

// InitializeInventory is an offline, explicit recovery-enrolled ceremony. It
// creates a full snapshot of the planned empty image before making inventory
// writable, so a failed backup cannot strand an enabled inventory.
func InitializeInventory(accessPath, snapshotPath, password, code string) error {
	if filepath.Base(accessPath) != "access.json" || sameDirectory(accessPath, snapshotPath) {
		return ErrUnsafeAccessStore
	}
	release, err := AcquireOperationLock(accessPath)
	if err != nil {
		return err
	}
	defer release()
	return withAccessWriteLock(accessPath, func() error {
		if _, err := readInventory(filepath.Join(filepath.Dir(accessPath), inventoryName)); err == nil {
			return ErrInventoryExists
		} else if !errors.Is(err, ErrInventoryMissing) {
			return err
		}
		body, err := readAccess(accessPath)
		if err != nil {
			return err
		}
		key, state, id, err := unsealBody(body, password)
		if err != nil {
			return err
		}
		defer clear(key)
		if state != ready || len(id) != 16 {
			return ErrChangeRequired
		}
		image, err := inventorystore.Create(key, id)
		if err != nil {
			return err
		}
		snapshot, err := createFullSnapshot(body, image, password, code)
		if err != nil {
			return err
		}
		if err := writeNewFullSnapshot(snapshotPath, snapshot); err != nil {
			return err
		}
		return createInventory(filepath.Join(filepath.Dir(accessPath), inventoryName), image)
	})
}

// ReadInventory requires a ready session's exact access revision and key.
// No public certificate record is returned before the whole image validates.
func ReadInventory(accessPath string, key, id []byte, expectedRevision [32]byte) ([]publicinventory.Record, uint64, error) {
	var records []publicinventory.Record
	var generation uint64
	err := withAccessWriteLock(accessPath, func() error {
		if err := checkInventoryRevision(accessPath, expectedRevision); err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(accessPath), inventoryName))
		if err != nil {
			return err
		}
		records, generation, err = inventorystore.Open(key, id, image)
		return err
	})
	return records, generation, err
}

// AppendInventory is an atomic single-file replacement under the installation
// writer lock. A post-rename error is uncertain and must not be retried blind.
func AppendInventory(accessPath string, key, id []byte, expectedRevision [32]byte, input []byte, owner, location string) ([]publicinventory.Record, uint64, error) {
	var added []publicinventory.Record
	var generation uint64
	err := withAccessWriteLock(accessPath, func() error {
		if err := checkInventoryRevision(accessPath, expectedRevision); err != nil {
			return err
		}
		path := filepath.Join(filepath.Dir(accessPath), inventoryName)
		image, err := readInventory(path)
		if err != nil {
			return err
		}
		next, batch, err := inventorystore.Append(key, id, image, input, owner, location)
		if err != nil {
			return err
		}
		if err := replaceInventory(path, next); err != nil {
			return err
		}
		added = batch
		_, generation, err = inventorystore.Open(key, id, next)
		return err
	})
	return added, generation, err
}

func checkInventoryRevision(accessPath string, expected [32]byte) error {
	body, err := readAccess(accessPath)
	if err != nil || sha256.Sum256(body) != expected {
		return ErrStaleUpgrade
	}
	return nil
}

// ExportFullSnapshot requires the daemon to be stopped. It captures access
// and inventory under the same lock, and writes a new separate private file.
func ExportFullSnapshot(accessPath, snapshotPath, password, code string) error {
	if filepath.Base(accessPath) != "access.json" || sameDirectory(accessPath, snapshotPath) {
		return ErrUnsafeAccessStore
	}
	release, err := AcquireOperationLock(accessPath)
	if err != nil {
		return err
	}
	defer release()
	return withAccessWriteLock(accessPath, func() error {
		body, err := readAccess(accessPath)
		if err != nil {
			return err
		}
		image, err := readInventory(filepath.Join(filepath.Dir(accessPath), inventoryName))
		if err != nil {
			return err
		}
		snapshot, err := createFullSnapshot(body, image, password, code)
		if err != nil {
			return err
		}
		return writeNewFullSnapshot(snapshotPath, snapshot)
	})
}

func VerifyFullSnapshot(snapshotPath, credential string, method SnapshotUnlock) ([]byte, uint64, error) {
	snapshot, err := readFullSnapshot(snapshotPath)
	if err != nil {
		return nil, 0, err
	}
	_, id, _, generation, err := openFullSnapshot(snapshot, credential, method)
	return id, generation, err
}

// RestoreFullSnapshot never overwrites an installation. It writes inventory
// first and access last, so a crash before completion cannot expose an access
// file pointing to absent inventory. A partially written destination is not
// automatically cleaned up; retry in a new empty private directory.
func RestoreFullSnapshot(snapshotPath, destinationAccessPath, credential string, method SnapshotUnlock) error {
	if filepath.Base(destinationAccessPath) != "access.json" || sameDirectory(snapshotPath, destinationAccessPath) {
		return ErrUnsafeAccessStore
	}
	snapshot, err := readFullSnapshot(snapshotPath)
	if err != nil {
		return err
	}
	body, _, image, _, err := openFullSnapshot(snapshot, credential, method)
	if err != nil {
		return err
	}
	release, err := AcquireOperationLock(destinationAccessPath)
	if err != nil {
		return err
	}
	defer release()
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
		inventoryPath := filepath.Join(filepath.Dir(destinationAccessPath), inventoryName)
		if err := createInventory(inventoryPath, image); err != nil {
			return err
		}
		root, err := openPrivateRoot(filepath.Dir(destinationAccessPath))
		if err != nil {
			return ErrInventoryUncertain
		}
		defer root.Close()
		f, err := root.OpenFile("access.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return ErrInventoryUncertain
		}
		if err := writeAndSyncFile(f, body); err != nil {
			return ErrInventoryUncertain
		}
		if err := syncAccessDirectory(destinationAccessPath); err != nil {
			return ErrInventoryUncertain
		}
		installed, err := readAccess(destinationAccessPath)
		if err != nil || !bytes.Equal(installed, body) {
			return ErrInventoryUncertain
		}
		return nil
	})
}

func writeNewFullSnapshot(path string, body []byte) error {
	root, err := openPrivateRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrSnapshotExists
		}
		return ErrUnsafeAccessStore
	}
	if err := writeAndSyncFile(f, body); err != nil {
		return ErrSnapshotUncertain
	}
	if err := syncAccessDirectory(path); err != nil {
		return ErrSnapshotUncertain
	}
	read, err := readFullSnapshot(path)
	if err != nil || !bytes.Equal(read, body) {
		return ErrSnapshotUncertain
	}
	return nil
}

func readFullSnapshot(path string) ([]byte, error) {
	return readPrivateFile(path, maxFullSnapshotFile, ErrInvalidFullSnapshot)
}
func readInventory(path string) ([]byte, error) {
	return readPrivateFile(path, 96<<20, ErrInvalidFullSnapshot)
}

func readPrivateFile(path string, limit int, invalid error) ([]byte, error) {
	root, err := openPrivateRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	listed, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) && name == inventoryName {
		return nil, ErrInventoryMissing
	}
	if err != nil || !listed.Mode().IsRegular() || listed.Mode().Perm()&0o077 != 0 {
		return nil, invalid
	}
	owner, ok := listed.Sys().(*syscall.Stat_t)
	if !ok || int64(owner.Uid) != int64(os.Geteuid()) {
		return nil, invalid
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, invalid
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(listed, opened) || opened.Mode().Perm()&0o077 != 0 {
		return nil, invalid
	}
	body, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil || len(body) == 0 || len(body) > limit {
		return nil, invalid
	}
	return body, nil
}

func createInventory(path string, body []byte) error {
	root, err := openPrivateRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(inventoryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrInventoryExists
		}
		return ErrUnsafeAccessStore
	}
	if err := writeAndSyncFile(f, body); err != nil {
		return ErrInventoryUncertain
	}
	if err := syncAccessDirectory(path); err != nil {
		return ErrInventoryUncertain
	}
	read, err := readInventory(path)
	if err != nil || !bytes.Equal(read, body) {
		return ErrInventoryUncertain
	}
	return nil
}

func replaceInventory(path string, body []byte) error {
	return replaceInventoryWithHooks(path, body, writeAndSyncFile, syncAccessDirectory)
}

func replaceInventoryWithSync(path string, body []byte, syncDir func(string) error) error {
	return replaceInventoryWithHooks(path, body, writeAndSyncFile, syncDir)
}

func replaceInventoryWithHooks(path string, body []byte, write func(*os.File, []byte) error, syncDir func(string) error) error {
	root, err := openPrivateRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	listed, err := root.Lstat(inventoryName)
	if err != nil || !listed.Mode().IsRegular() || listed.Mode().Perm()&0o077 != 0 {
		return ErrInvalidFullSnapshot
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return ErrInvalidFullSnapshot
	}
	name := ".rootwell-inventory-" + hex.EncodeToString(random)
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrUnsafeAccessStore
	}
	defer root.Remove(name)
	if err := write(f, body); err != nil {
		_ = f.Close()
		return ErrInvalidFullSnapshot
	}
	if err := root.Rename(name, inventoryName); err != nil {
		return ErrInvalidFullSnapshot
	}
	if err := syncDir(path); err != nil {
		return ErrInventoryUncertain
	}
	read, err := readInventory(path)
	if err != nil || !bytes.Equal(read, body) {
		return ErrInventoryUncertain
	}
	return nil
}
