//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/vault"
)

var recoveryCodeLine = regexp.MustCompile(`RW1-[A-Z2-7-]+`)

// withRecord puts one record in the installed vault, to find again later.
func withRecord(t *testing.T, data, keyFile string) string {
	t.Helper()
	key, err := vault.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(data, key)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	id := v.Index("note", "kept")
	if err := v.Update(func(tx *vault.Tx) error { return tx.Put("note", id, []byte("still here")) }); err != nil {
		t.Fatal(err)
	}
	return id
}

func readRecord(t *testing.T, data string, key []byte, id string) (string, error) {
	t.Helper()
	v, err := vault.Open(data, key)
	if err != nil {
		return "", err
	}
	defer v.Close()
	var got []byte
	err = v.View(func(tx *vault.Tx) error {
		var err error
		got, _, err = tx.Get("note", id)
		return err
	})
	return string(got), err
}

func TestLinuxKeyExportPrintsTheCodeOfTheKeyThatOpensTheVault(t *testing.T) {
	data, keyFile, _ := installed(t)
	key, err := vault.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runOfflineCommand([]string{"key-export", data, keyFile}, ceremonySecrets(t), &out); err != nil {
		t.Fatal(err)
	}
	printed, err := vault.ParseRecoveryCode(recoveryCodeLine.FindString(out.String()))
	if err != nil || !bytes.Equal(printed, key) {
		t.Fatalf("key-export printed another key: %v", err)
	}
	v, err := vault.Open(data, key)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	out.Reset()
	if err := runOfflineCommand([]string{"key-export", data, keyFile}, ceremonySecrets(t), &out); err == nil || out.Len() != 0 {
		t.Fatalf("key-export beside a running rootwelld: %v %q", err, out.String())
	}
}

func TestLinuxKeyRotationNeedsSAVEDAndLeavesOnlyTheNewKey(t *testing.T) {
	data, keyFile, _ := installed(t)
	id := withRecord(t, data, keyFile)
	oldKey, err := vault.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runOfflineCommand([]string{"key-rotate", data, keyFile}, ceremonySecrets(t, "later"), &out); err == nil {
		t.Fatal("a rotation went ahead without SAVED")
	}
	if got, err := readRecord(t, data, oldKey, id); err != nil || got != "still here" {
		t.Fatalf("a refused rotation changed the vault: %q %v", got, err)
	}
	if _, err := os.Lstat(keyFile + ".new"); !os.IsNotExist(err) {
		t.Fatal("a refused rotation left a new key file")
	}
	out.Reset()
	if err := runOfflineCommand([]string{"key-rotate", data, keyFile}, ceremonySecrets(t, "SAVED"), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "nothing left in its file opens with the old one") {
		t.Fatalf("the rotation did not rewrite the file: %q", out.String())
	}
	newKey, err := vault.ReadKeyFile(keyFile)
	if err != nil || bytes.Equal(newKey, oldKey) {
		t.Fatalf("the key file was not replaced: %v", err)
	}
	printed, err := vault.ParseRecoveryCode(recoveryCodeLine.FindString(out.String()))
	if err != nil || !bytes.Equal(printed, newKey) {
		t.Fatalf("the printed code is not the new key: %v", err)
	}
	if _, err := readRecord(t, data, oldKey, id); err == nil {
		t.Fatal("the old key still opens the vault")
	}
	if got, err := readRecord(t, data, newKey, id); err != nil || got != "still here" {
		t.Fatalf("after rotation: %q %v", got, err)
	}
	if _, err := os.Lstat(keyFile + ".new"); !os.IsNotExist(err) {
		t.Fatal("the rotation left its new key file behind")
	}
	// A leftover from an interrupted rotation is named, never overwritten.
	if err := os.WriteFile(keyFile+".new", []byte("leftover"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	err = runOfflineCommand([]string{"key-rotate", data, keyFile}, ceremonySecrets(t, "SAVED"), &out)
	if err == nil || !strings.Contains(err.Error(), keyFile+".new") || out.Len() != 0 {
		t.Fatalf("a leftover rotation file: %v %q", err, out.String())
	}
}

func TestLinuxRestoreWritesABackupOnlyIntoAnEmptyDirectoryAndOnlyIfItOpens(t *testing.T) {
	data, keyFile, _ := installed(t)
	id := withRecord(t, data, keyFile)
	key, err := vault.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	code, err := vault.RecoveryCode(key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(data, key)
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "rootwell-backup.db")
	f, err := os.Create(backup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Backup(f); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	_ = v.Close()
	restore := func(dir, keyFile string, secrets ...string) error {
		var out bytes.Buffer
		return runOfflineCommand([]string{"restore", backup, dir, keyFile}, ceremonySecrets(t, secrets...), &out)
	}
	// Never over an installation.
	if err := restore(data, keyFile); err == nil {
		t.Fatal("restore wrote over a data directory in use")
	}
	// Another key keeps nothing.
	other := filepath.Join(ceremonyPrivateDir(t), "other.key")
	otherKey, _ := vault.NewInstanceKey()
	if err := vault.WriteKeyFile(other, otherKey); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "restored")
	if err := restore(empty, other); err == nil {
		t.Fatal("a backup was kept under another key")
	}
	if entries, _ := os.ReadDir(empty); len(entries) != 0 {
		t.Fatalf("a refused restore left %d files", len(entries))
	}
	// The right key file.
	if err := restore(empty, keyFile); err != nil {
		t.Fatal(err)
	}
	if got, err := readRecord(t, empty, key, id); err != nil || got != "still here" {
		t.Fatalf("restored: %q %v", got, err)
	}
	// No key file: the recovery code restores the vault and the key file.
	again := filepath.Join(t.TempDir(), "again")
	lostKey := filepath.Join(ceremonyPrivateDir(t), "lost.key")
	if err := restore(again, lostKey, "RW1-NOT-A-CODE"); err == nil {
		t.Fatal("a wrong recovery code was taken")
	}
	if err := restore(again, lostKey, code); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := vault.ReadKeyFile(lostKey)
	if err != nil || !bytes.Equal(rebuilt, key) {
		t.Fatalf("the key file was not rebuilt from the code: %v", err)
	}
	if got, err := readRecord(t, again, key, id); err != nil || got != "still here" {
		t.Fatalf("restored with the code: %q %v", got, err)
	}
}

func TestLinuxInitShowsNoCodeForAKeyDirectoryOthersCanRead(t *testing.T) {
	data := filepath.Join(ceremonyPrivateDir(t), "data")
	loose := t.TempDir()
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := initialize(data, filepath.Join(loose, "instance.key"), strings.NewReader("SAVED\n"), &out); err == nil || out.Len() != 0 {
		t.Fatalf("init with a loose key directory: %v %q", err, out.String())
	}
	if _, err := os.Lstat(filepath.Join(loose, "instance.key")); !os.IsNotExist(err) {
		t.Fatal("a key file was written into a loose directory")
	}
}
