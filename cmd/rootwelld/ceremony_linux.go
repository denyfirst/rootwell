//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/accountstore"
	"github.com/denyfirst/rootwell/internal/servingstore"
	"github.com/denyfirst/rootwell/internal/vault"
)

var errOfflineUsage = errors.New("invalid offline command or arguments; see rootwelld usage")

func runOfflineCommand(args []string, read secretReader, out io.Writer) error {
	switch args[0] {
	case "key-restore":
		return restoreKeyFile(args, read, out)
	case "setup-code":
		return printSetupCode(args, out)
	case "serving-names":
		return setServingNames(args, out)
	case "key-export":
		return exportKey(args, out)
	case "key-rotate":
		return rotateKey(args, read, out)
	case "restore":
		return restoreBackup(args, read, out)
	default:
		return errOfflineUsage
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

// printSetupCode makes a new setup code, with the service stopped. Without a
// name it makes the first account. With one, it replaces that account's
// password and phone: the way back after losing both the phone and the
// recovery codes, or the password.
func printSetupCode(args []string, out io.Writer) error {
	if len(args) != 3 && len(args) != 4 {
		return errOfflineUsage
	}
	dir, keyFile := args[1], args[2]
	if err := keyOutsideData(dir, keyFile); err != nil {
		return err
	}
	name := ""
	if len(args) == 4 {
		var ok bool
		if name, ok = accountstore.Name(args[3]); !ok {
			return errors.New("that is not an account name")
		}
	}
	key, err := vault.ReadKeyFile(keyFile)
	if err != nil {
		return errors.New("the instance key file could not be read; it must be a private 0600 file of this user")
	}
	v, err := vault.Open(dir, key)
	clear(key)
	if err != nil {
		return errors.New("the vault did not open with this key, or rootwelld is still running; stop it first")
	}
	defer v.Close()
	code, until, err := accountstore.New(v, time.Now).NewSetupCode(name)
	switch {
	case errors.Is(err, accountstore.ErrRefused) && name == "":
		return errors.New("an account exists already; to replace how it signs in, add its name: rootwelld setup-code <data-dir> <key-file> <name>")
	case errors.Is(err, accountstore.ErrRefused):
		return errors.New("there is no account with that name")
	case err != nil:
		return errors.New("the setup code could not be saved")
	}
	return showSetupCode(out, code, until, name)
}

// setServingNames makes a new certificate authority for the names Rootwell
// answers to besides this host's loopback names: LAN or VPN DNS names and IP
// addresses. The service must be stopped. Browsers that trusted the old
// authority must trust the new one; its fingerprint is printed for that.
func setServingNames(args []string, out io.Writer) error {
	if len(args) < 3 {
		return errOfflineUsage
	}
	dir, keyFile := args[1], args[2]
	if err := keyOutsideData(dir, keyFile); err != nil {
		return err
	}
	key, err := vault.ReadKeyFile(keyFile)
	if err != nil {
		return errors.New("the instance key file could not be read; it must be a private 0600 file of this user")
	}
	v, err := vault.Open(dir, key)
	clear(key)
	if err != nil {
		return errors.New("the vault did not open with this key, or rootwelld is still running; stop it first")
	}
	defer v.Close()
	s, err := servingstore.SetNames(v, args[3:], time.Now())
	switch {
	case errors.Is(err, servingstore.ErrRefused):
		return errors.New("one of those is not a name Rootwell can serve: give IP addresses, or DNS names with a dot such as rootwell.lan; no wildcards, at most 16 in all")
	case err != nil:
		return errors.New("the new certificate authority could not be saved")
	}
	names := append([]string{"localhost", "127.0.0.1", "::1"}, s.Added...)
	_, err = fmt.Fprintf(out, "Rootwell's new certificate authority covers %s. Its SHA-256 fingerprint:\n\n  %s\n\nBrowsers that trusted the old one must trust this one instead: once rootwelld runs again, download /rootwell-ca.pem and compare the fingerprint. To answer on a LAN address, start rootwelld with --listen <address>.\n",
		strings.Join(names, ", "), s.Fingerprint())
	return err
}
