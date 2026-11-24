//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/account"
	"github.com/denyfirst/rootwell/internal/accountstore"
	"github.com/denyfirst/rootwell/internal/vault"
)

func ceremonyPrivateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func ceremonySecrets(t *testing.T, secrets ...string) secretReader {
	t.Helper()
	next := 0
	return func(string) (string, error) {
		if next >= len(secrets) {
			t.Fatal("command requested an unexpected secret")
		}
		value := secrets[next]
		next++
		return value, nil
	}
}

// A setup code is four groups of six base32 letters.
var setupCodeLine = regexp.MustCompile(`^[a-z2-7]{6}(-[a-z2-7]{6}){3}$`)

// printedSetupCode finds the one setup code a command printed.
func printedSetupCode(t *testing.T, output string) string {
	t.Helper()
	var found []string
	for _, line := range strings.Split(output, "\n") {
		if candidate := strings.TrimSpace(line); setupCodeLine.MatchString(candidate) {
			found = append(found, candidate)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want one setup code printed, found %d", len(found))
	}
	return found[0]
}

// installed runs init, as an operator does, and returns the data directory,
// the key file and what init printed.
func installed(t *testing.T) (string, string, string) {
	t.Helper()
	data, keyFile := ceremonyPrivateDir(t), filepath.Join(ceremonyPrivateDir(t), "instance.key")
	var output bytes.Buffer
	if err := initialize(data, keyFile, strings.NewReader("SAVED\n"), &output); err != nil {
		t.Fatal(err)
	}
	return data, keyFile, output.String()
}

// openAccounts opens the vault with its key file, as rootwelld serve does.
func openAccounts(t *testing.T, data, keyFile string) (*accountstore.Store, func()) {
	t.Helper()
	key, err := vault.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	v, err := vault.Open(data, key)
	if err != nil {
		t.Fatal(err)
	}
	return accountstore.New(v, time.Now), func() {
		if err := v.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxInitNeedsSAVEDAndLeavesAWorkingSetupCode(t *testing.T) {
	data := filepath.Join(ceremonyPrivateDir(t), "data")
	keyFile := filepath.Join(ceremonyPrivateDir(t), "instance.key")
	// Without SAVED, init shows the key's recovery code and writes nothing.
	for _, answer := range []string{"", "\n", "saved\n", "no\n"} {
		var output bytes.Buffer
		if err := initialize(data, keyFile, strings.NewReader(answer), &output); err == nil || !strings.Contains(output.String(), "RW1-") {
			t.Fatalf("init went on after %q: %v", answer, err)
		}
		if _, err := os.Lstat(keyFile); !os.IsNotExist(err) {
			t.Fatalf("init wrote the key file after %q", answer)
		}
		if entries, err := os.ReadDir(data); err != nil || len(entries) != 0 {
			t.Fatalf("init wrote in the data directory after %q: %v", answer, err)
		}
	}
	var output bytes.Buffer
	if err := initialize(data, keyFile, strings.NewReader("SAVED\n"), &output); err != nil {
		t.Fatal(err)
	}
	key, err := vault.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := vault.RecoveryCode(key)
	if err != nil || strings.Count(output.String(), recovery) != 1 {
		t.Fatal("init did not print the key file's recovery code once")
	}
	code := printedSetupCode(t, output.String())
	accounts, done := openAccounts(t, data, keyFile)
	if exists, err := accounts.Exists(); err != nil || exists {
		t.Fatalf("init made an account: %v", err)
	}
	if err := accounts.CheckSetup(code, "ada"); err != nil {
		t.Fatalf("the printed setup code does not work: %v", err)
	}
	done()

	// A second init on the same installation refuses before showing or
	// writing anything, with the same key file or another.
	other := filepath.Join(ceremonyPrivateDir(t), "other.key")
	for _, k := range []string{keyFile, other} {
		var again bytes.Buffer
		if err := initialize(data, k, strings.NewReader("SAVED\n"), &again); err == nil || again.Len() != 0 {
			t.Fatalf("a second init was not refused: %v", err)
		}
	}
	if _, err := os.Lstat(other); !os.IsNotExist(err) {
		t.Fatal("a refused init wrote a key file")
	}
	if kept, err := vault.ReadKeyFile(keyFile); err != nil || !bytes.Equal(kept, key) {
		t.Fatal("a refused init changed the key file")
	}
	accounts, done = openAccounts(t, data, keyFile)
	defer done()
	if err := accounts.CheckSetup(code, "ada"); err != nil {
		t.Fatalf("a refused init changed the setup code: %v", err)
	}
}

func TestLinuxSetupCodeMakesTheFirstAccountOrReplacesItsSignIn(t *testing.T) {
	data, keyFile, printed := installed(t)
	first := printedSetupCode(t, printed)
	setupCode := func(args ...string) (string, error) {
		var output bytes.Buffer
		err := runOfflineCommand(append([]string{"setup-code", data, keyFile}, args...), ceremonySecrets(t), &output)
		if err != nil && output.Len() != 0 {
			t.Fatalf("a refused setup-code printed: %q", output.String())
		}
		return output.String(), err
	}

	// No account yet: a new code replaces the one init printed.
	output, err := setupCode()
	if err != nil {
		t.Fatal(err)
	}
	code := printedSetupCode(t, output)
	accounts, done := openAccounts(t, data, keyFile)
	if err := accounts.CheckSetup(code, "ada"); err != nil {
		t.Fatalf("the new setup code does not work: %v", err)
	}
	if err := accounts.CheckSetup(first, "ada"); !errors.Is(err, accountstore.ErrRefused) {
		t.Fatalf("the earlier setup code still works: %v", err)
	}
	// The setup page makes the account with it.
	hash, err := account.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := account.NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := accounts.FinishSetup(code, "ada", hash, seed, time.Now().Unix()/30); err != nil {
		t.Fatal(err)
	}
	done()

	// With an account, a code needs the account's name.
	if _, err := setupCode(); err == nil || !strings.Contains(err.Error(), "<name>") {
		t.Fatalf("a first-account code with an account present: %v", err)
	}
	for _, name := range []string{"bob", "not a name"} {
		if _, err := setupCode(name); err == nil {
			t.Fatalf("a setup code for %q was made", name)
		}
	}
	output, err = setupCode("ada")
	if err != nil {
		t.Fatal(err)
	}
	reset := printedSetupCode(t, output)
	accounts, done = openAccounts(t, data, keyFile)
	if err := accounts.CheckSetup(reset, "ada"); err != nil {
		t.Fatalf("the reset code does not work for its account: %v", err)
	}
	if err := accounts.CheckSetup(reset, "bob"); !errors.Is(err, accountstore.ErrRefused) {
		t.Fatalf("the reset code works for another name: %v", err)
	}
	// While rootwelld holds the vault, setup-code refuses and changes nothing.
	if _, err := setupCode("ada"); err == nil {
		t.Fatal("setup-code ran while the vault was held open")
	}
	if err := accounts.CheckSetup(reset, "ada"); err != nil {
		t.Fatalf("a refused setup-code replaced the code: %v", err)
	}
	done()

	for _, args := range [][]string{{"setup-code", data}, {"setup-code", data, keyFile, "ada", "extra"}, {"setup-code", data, filepath.Join(data, "instance.key")}, {"setup-code", data, filepath.Join(ceremonyPrivateDir(t), "missing.key")}} {
		var output bytes.Buffer
		if err := runOfflineCommand(args, ceremonySecrets(t), &output); err == nil || output.Len() != 0 {
			t.Fatalf("bad arguments accepted: %v", args)
		}
	}
	if err := runOfflineCommand([]string{"setup-code", data}, ceremonySecrets(t), &bytes.Buffer{}); !errors.Is(err, errOfflineUsage) {
		t.Fatalf("missing arguments: %v", err)
	}
}

func TestKeyRestoreRebuildsTheKeyFileAndNeverReplacesOne(t *testing.T) {
	data, keyFile, _ := installed(t)
	var output bytes.Buffer
	original, err := vault.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	code, err := vault.RecoveryCode(original)
	if err != nil {
		t.Fatal(err)
	}
	// An existing key file is never replaced, even by the right code.
	if err := runOfflineCommand([]string{"key-restore", data, keyFile}, ceremonySecrets(t, code), &output); err == nil {
		t.Fatal("key-restore replaced an existing key file")
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	// A code that does not open this vault writes nothing.
	other, _ := vault.NewInstanceKey()
	otherCode, _ := vault.RecoveryCode(other)
	if err := runOfflineCommand([]string{"key-restore", data, keyFile}, ceremonySecrets(t, otherCode), &output); err == nil {
		t.Fatal("a code from another installation was accepted")
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatal("a refused restore wrote a key file")
	}
	for _, args := range [][]string{{"key-restore", data}, {"key-restore", data, filepath.Join(data, "instance.key")}} {
		if err := runOfflineCommand(args, ceremonySecrets(t, code), &output); err == nil {
			t.Fatalf("bad arguments accepted: %v", args)
		}
	}
	output.Reset()
	if err := runOfflineCommand([]string{"key-restore", data, keyFile}, ceremonySecrets(t, code), &output); err != nil {
		t.Fatal(err)
	}
	restored, err := vault.ReadKeyFile(keyFile)
	if err != nil || !bytes.Equal(restored, original) || strings.Contains(output.String(), code) {
		t.Fatalf("restore: %v", err)
	}
	if v, err := vault.Open(data, restored); err != nil {
		t.Fatalf("the restored key does not open the vault: %v", err)
	} else {
		_ = v.Close()
	}
}
