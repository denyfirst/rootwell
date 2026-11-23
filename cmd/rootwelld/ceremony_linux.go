//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/vault"
)

var errOfflineUsage = errors.New("invalid offline recovery command or arguments; see rootwelld usage")

func runOfflineCommand(args []string, read secretReader, out io.Writer) error {
	switch args[0] {
	case "key-restore":
		return restoreKeyFile(args, read, out)
	case "recovery-enroll", "recovery-rotate", "recovery-reset":
		if len(args) != 2 {
			return errOfflineUsage
		}
		path := filepath.Join(args[1], "access.json")
		if args[0] == "recovery-reset" {
			code, err := read("Recovery code: ")
			if err != nil {
				return err
			}
			next, err := read("New login password: ")
			if err != nil {
				return err
			}
			confirm, err := read("Repeat new login password: ")
			if err != nil {
				return err
			}
			if next != confirm {
				return errors.New("new passwords do not match")
			}
			newCode, err := instanceaccess.RecoverPassword(path, code, next)
			if err != nil {
				return err
			}
			return showRecoveryCode(out, newCode)
		}
		password, err := read("Current login password: ")
		if err != nil {
			return err
		}
		var code string
		if args[0] == "recovery-enroll" {
			code, err = instanceaccess.EnrollRecovery(path, password)
		} else {
			code, err = instanceaccess.RotateRecovery(path, password)
		}
		if err != nil {
			return err
		}
		return showRecoveryCode(out, code)
	case "access-snapshot":
		if len(args) != 3 {
			return errOfflineUsage
		}
		password, err := read("Current login password: ")
		if err != nil {
			return err
		}
		code, err := read("Recovery code: ")
		if err != nil {
			return err
		}
		if err := instanceaccess.ExportAccessSnapshot(filepath.Join(args[1], "access.json"), args[2], password, code); err != nil {
			return err
		}
		_, err = io.WriteString(out, "Access-only snapshot written and verified. It does not contain certificate inventory or vault data.\n")
		return err
	case "access-verify", "access-restore":
		want := 3
		if args[0] == "access-restore" {
			want = 4
		}
		if len(args) != want {
			return errOfflineUsage
		}
		method, err := parseUnlockMethod(args[len(args)-1])
		if err != nil {
			return err
		}
		credential, err := read("Snapshot password or recovery code: ")
		if err != nil {
			return err
		}
		if args[0] == "access-verify" {
			id, err := instanceaccess.VerifyAccessSnapshot(args[1], credential, method)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(out, "Access-only snapshot authenticated. Installation ID: %x\n", id)
			return err
		}
		path := filepath.Join(args[2], "access.json")
		if err := instanceaccess.RestoreAccessSnapshot(args[1], path, credential, method); err != nil {
			return err
		}
		message := "Access-only snapshot restored into a fresh private directory.\n"
		if method == instanceaccess.SnapshotRecoveryCode {
			message += "If the old password is lost, run recovery-reset on the restored directory before starting rootwelld.\n"
		}
		_, err = io.WriteString(out, message)
		return err
	default:
		return errOfflineUsage
	}
}

func parseUnlockMethod(value string) (instanceaccess.SnapshotUnlock, error) {
	switch value {
	case "password":
		return instanceaccess.SnapshotPassword, nil
	case "code":
		return instanceaccess.SnapshotRecoveryCode, nil
	default:
		return 0, errOfflineUsage
	}
}

// restoreKeyFile rebuilds a lost instance key file from the recovery code init
// printed. The code is read from the terminal, never from argv. The key must
// open this installation's vault before anything is written, and an existing
// key file is never replaced. The service must be stopped: it holds the vault.
func restoreKeyFile(args []string, read secretReader, out io.Writer) error {
	if len(args) != 3 {
		return errOfflineUsage
	}
	dir, keyFile := args[1], args[2]
	if err := keyOutsideData(dir, keyFile); err != nil {
		return err
	}
	code, err := read("Instance key recovery code: ")
	if err != nil {
		return err
	}
	key, err := vault.ParseRecoveryCode(code)
	if err != nil {
		return errors.New("that is not an instance key recovery code; check it against the copy you wrote down")
	}
	defer clear(key)
	v, err := vault.Open(dir, key)
	if err != nil {
		return errors.New("that recovery code does not open the vault in this data directory, or rootwelld is still running; nothing was written")
	}
	if err := v.Close(); err != nil {
		return errors.New("the vault could not be closed cleanly; nothing was written")
	}
	if err := vault.WriteKeyFile(keyFile, key); err != nil {
		return errors.New("the key file was not written: its directory must be private (0700) to this user, and the file must not exist yet")
	}
	_, err = io.WriteString(out, "Instance key file restored. Start rootwelld with it.\n")
	return err
}
