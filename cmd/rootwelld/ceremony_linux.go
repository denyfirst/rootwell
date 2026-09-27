//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

var errOfflineUsage = errors.New("invalid offline recovery command or arguments; see rootwelld usage")

func runOfflineCommand(args []string, read secretReader, out io.Writer) error {
	switch args[0] {
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
