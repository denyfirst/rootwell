//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/denyfirst/rootwell/internal/vault"
)

// maxBackup is the largest backup restore reads: the vault's own limit.
const maxBackup = 512 << 20

// openVault opens the vault in dir with the key in keyFile, with the service
// stopped: a running rootwelld holds the vault.
func openVault(dir, keyFile string) (*vault.Store, []byte, error) {
	if err := keyOutsideData(dir, keyFile); err != nil {
		return nil, nil, err
	}
	key, err := vault.ReadKeyFile(keyFile)
	if err != nil {
		return nil, nil, errors.New("the instance key file could not be read; it must be a private 0600 file of this user")
	}
	v, err := vault.Open(dir, key)
	if err != nil {
		clear(key)
		return nil, nil, errors.New("the vault did not open with this key, or rootwelld is still running; stop it first")
	}
	return v, key, nil
}

// exportKey prints the recovery code of the key that opens this vault again.
func exportKey(args []string, out io.Writer) error {
	if len(args) != 3 {
		return errOfflineUsage
	}
	v, key, err := openVault(args[1], args[2])
	if err != nil {
		return err
	}
	defer clear(key)
	if err := v.Close(); err != nil {
		return errors.New("the vault could not be closed cleanly")
	}
	code, err := vault.RecoveryCode(key)
	if err != nil {
		return errors.New("the recovery code could not be made")
	}
	_, err = fmt.Fprintf(out, "Instance key recovery code for %s (keep it apart from this host and from backups):\n\n  %s\n", args[2], code)
	return err
}

// rotateKey moves the vault to a new instance key. The new key's recovery
// code is shown first and must be confirmed as saved. The new key is written
// beside the old one, the vault moves to it in one transaction, and then it
// takes the old key file's place.
func rotateKey(args []string, read secretReader, out io.Writer) error {
	if len(args) != 3 {
		return errOfflineUsage
	}
	keyFile := args[2]
	pending := keyFile + ".new"
	// #nosec G703 -- pending is derived from a local operator CLI path.
	if _, err := os.Lstat(pending); !os.IsNotExist(err) {
		return fmt.Errorf("an earlier rotation left %s. If rootwelld does not start with %s, the vault moved to that key already: rename it to %s. Otherwise remove it, then rotate again", pending, keyFile, keyFile)
	}
	if vault.KeyDirectoryReady(keyFile) != nil {
		return errors.New("the key file's directory must be a private (0700) directory of this user; nothing was changed")
	}
	dir := args[1]
	v, key, err := openVault(dir, keyFile)
	if err != nil {
		return err
	}
	clear(key)
	open := true
	defer func() {
		if open {
			_ = v.Close()
		}
	}()
	next, err := vault.NewInstanceKey()
	if err != nil {
		return errors.New("a new instance key could not be made")
	}
	defer clear(next)
	code, err := vault.RecoveryCode(next)
	if err != nil {
		return errors.New("a new instance key could not be made")
	}
	if _, err := fmt.Fprintf(out, "New instance key recovery code (shown only here). After the rotation only the new key opens this vault; backups made before keep opening with the old key and its old code only:\n\n  %s\n\n", code); err != nil {
		return errors.New("the new recovery code could not be shown; nothing was changed")
	}
	answer, err := read("Type SAVED once it is written down: ")
	if err != nil || strings.TrimSpace(answer) != "SAVED" {
		return errors.New("nothing was changed, because saving the new recovery code was not confirmed")
	}
	if err := vault.WriteKeyFile(pending, next); err != nil {
		return errors.New("the new key file could not be written beside the old one; nothing was changed")
	}
	rotateErr := v.Rotate(next)
	_ = v.Close()
	open = false
	if rotateErr != nil {
		// A failed commit may still have reached the disk: keep the new key
		// if it opens the vault, and remove it only when it does not.
		check, err := vault.Open(dir, next)
		if err != nil {
			// #nosec G703 -- pending is derived from a local operator CLI path.
			_ = os.Remove(pending)
			return errors.New("the vault could not move to the new key; nothing was changed")
		}
		_ = check.Close()
	}
	// Freed pages of the file still hold records under the old key until the
	// file is rewritten without them.
	compactErr := vault.Compact(dir, next)
	// #nosec G703 -- both paths are local operator CLI paths.
	if err := os.Rename(pending, keyFile); err != nil {
		return fmt.Errorf("the vault now opens only with %s: rename it to %s before starting rootwelld", pending, keyFile)
	}
	syncDir(filepath.Dir(keyFile))
	if compactErr != nil {
		_, err = io.WriteString(out, "The vault now opens with the new key in "+keyFile+", but rewriting its file failed: until that succeeds, old pages in it may still open with the old key. Run rootwelld key-rotate once more.\n")
		return err
	}
	_, err = io.WriteString(out, "The vault now opens with the new key in "+keyFile+", and nothing left in its file opens with the old one. Start rootwelld again.\n")
	return err
}

func syncDir(dir string) {
	// #nosec G304 G703 -- dir is a local operator CLI path.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// restoreBackup writes a backup into an empty data directory, and keeps it
// only once it opens with the instance key. Without the key file it asks for
// the key's recovery code, and writes the key file from it too.
func restoreBackup(args []string, read secretReader, out io.Writer) error {
	if len(args) != 4 {
		return errOfflineUsage
	}
	backup, dir, keyFile := args[1], args[2], args[3]
	if err := keyOutsideData(dir, keyFile); err != nil {
		return err
	}
	// #nosec G703 -- dir is a local operator CLI path, never an HTTP input.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("the data directory could not be made")
	}
	if err := privateDirectory(dir); err != nil {
		return err
	}
	// #nosec G703 -- dir is a local operator CLI path.
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		return errors.New("restore writes only into an empty data directory: move the current one aside first")
	}
	var key []byte
	writeKey := false
	// #nosec G703 -- keyFile is a local operator CLI path.
	if _, err := os.Lstat(keyFile); err == nil {
		if key, err = vault.ReadKeyFile(keyFile); err != nil {
			return errors.New("the instance key file could not be read; it must be a private 0600 file of this user")
		}
	} else {
		code, err := read("The key file is missing. Instance key recovery code: ")
		if err != nil {
			return err
		}
		if key, err = vault.ParseRecoveryCode(code); err != nil {
			return errors.New("that is not an instance key recovery code; check it against the copy you wrote down")
		}
		writeKey = true
	}
	defer clear(key)
	// The data directory is pinned: nothing written below can leave it.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return errors.New("the data directory could not be opened")
	}
	defer root.Close()
	if err := copyBackup(backup, root); err != nil {
		return err
	}
	syncDir(dir)
	v, err := vault.Open(dir, key)
	if err != nil {
		_ = root.Remove("rootwell.db")
		return errors.New("that backup does not open with this key; nothing was kept. A backup opens with the key the vault had when it was made")
	}
	if err := v.Close(); err != nil {
		return errors.New("the restored vault could not be closed cleanly")
	}
	if writeKey {
		if err := vault.WriteKeyFile(keyFile, key); err != nil {
			return errors.New("the backup is restored, but the key file could not be written: run rootwelld key-restore")
		}
	}
	_, err = io.WriteString(out, "Backup restored into "+dir+". Start rootwelld with it: accounts, passkeys and certificates are as they were when the backup was made.\n")
	return err
}

// copyBackup copies the backup file into the data directory as the vault
// file, through a temporary name, synced before it takes its place.
func copyBackup(backup string, root *os.Root) error {
	// #nosec G304 G703 -- backup is a local operator CLI path.
	in, err := os.Open(backup)
	if err != nil {
		return errors.New("the backup file could not be read")
	}
	defer in.Close()
	const part = "rootwell.db.part"
	f, err := root.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("the restored vault could not be written")
	}
	n, copyErr := io.Copy(f, io.LimitReader(in, maxBackup+1))
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || n == 0 || n > maxBackup {
		_ = root.Remove(part)
		return errors.New("the backup could not be copied: it is empty, too large, or unreadable")
	}
	if err := root.Rename(part, "rootwell.db"); err != nil {
		_ = root.Remove(part)
		return errors.New("the restored vault could not take its place")
	}
	return nil
}
