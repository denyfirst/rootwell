//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
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

func displayedCode(t *testing.T, output string) string {
	t.Helper()
	parts := strings.Split(output, "\n")
	for _, part := range parts {
		candidate := strings.TrimSpace(part)
		if len(candidate) == 64 && strings.Count(candidate, "-") == 12 {
			return candidate
		}
	}
	t.Fatal("recovery code was not displayed")
	return ""
}

func TestLinuxOfflineCeremonyEnrolsSnapshotsRestoresAndResets(t *testing.T) {
	dir := ceremonyPrivateDir(t)
	path := filepath.Join(dir, "access.json")
	const initial = "a sufficiently long setup password"
	const password = "a sufficiently long login password"
	if err := instanceaccess.Create(path, initial); err != nil {
		t.Fatal(err)
	}
	if err := instanceaccess.ChangeInitialPassword(path, initial, password); err != nil {
		t.Fatal(err)
	}
	key, id, err := instanceaccess.OpenWithIdentity(path, password)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runOfflineCommand([]string{"recovery-enroll", dir}, ceremonySecrets(t, password), &output); err != nil {
		t.Fatal(err)
	}
	code := displayedCode(t, output.String())
	backupPath := filepath.Join(ceremonyPrivateDir(t), "snapshot.rwab")
	output.Reset()
	if err := runOfflineCommand([]string{"access-snapshot", dir, backupPath}, ceremonySecrets(t, password, code), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), password) || strings.Contains(output.String(), code) {
		t.Fatal("snapshot confirmation leaked a credential")
	}
	output.Reset()
	if err := runOfflineCommand([]string{"access-verify", backupPath, "code"}, ceremonySecrets(t, code), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "authenticated") {
		t.Fatal("verification did not confirm authenticated snapshot")
	}
	fresh := ceremonyPrivateDir(t)
	output.Reset()
	if err := runOfflineCommand([]string{"access-restore", backupPath, fresh, "code"}, ceremonySecrets(t, code), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "recovery-reset") {
		t.Fatal("code restore failed to explain password reset")
	}
	const next = "a sufficiently long restored password"
	output.Reset()
	if err := runOfflineCommand([]string{"recovery-reset", fresh}, ceremonySecrets(t, code, next, next), &output); err != nil {
		t.Fatal(err)
	}
	newCode := displayedCode(t, output.String())
	if newCode == code {
		t.Fatal("reset did not rotate recovery code")
	}
	restoredKey, restoredID, err := instanceaccess.OpenWithIdentity(filepath.Join(fresh, "access.json"), next)
	if err != nil || !bytes.Equal(restoredKey, key) || !bytes.Equal(restoredID, id) {
		t.Fatalf("ceremony changed installation key or ID: %v", err)
	}
}

func TestLinuxOfflineCeremonyRefusesRunningDaemonAndBadArguments(t *testing.T) {
	dir := ceremonyPrivateDir(t)
	path := filepath.Join(dir, "access.json")
	const initial = "a sufficiently long setup password"
	const password = "a sufficiently long login password"
	if err := instanceaccess.Create(path, initial); err != nil {
		t.Fatal(err)
	}
	if err := instanceaccess.ChangeInitialPassword(path, initial, password); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runOfflineCommand([]string{"recovery-enroll"}, ceremonySecrets(t), &output); !errors.Is(err, errOfflineUsage) || output.Len() != 0 {
		t.Fatalf("bad arguments used secrets or emitted output: %v", err)
	}
	if err := runOfflineCommand([]string{"recovery-enroll", dir, "secret-must-not-be-argv"}, ceremonySecrets(t), &output); !errors.Is(err, errOfflineUsage) || output.Len() != 0 {
		t.Fatalf("secret-bearing extra argument was accepted: %v", err)
	}
	release, err := instanceaccess.AcquireOperationLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := runOfflineCommand([]string{"recovery-enroll", dir}, ceremonySecrets(t, password), &output); !errors.Is(err, instanceaccess.ErrOperationBusy) || output.Len() != 0 {
		t.Fatalf("recovery proceeded while daemon lock held: %v", err)
	}
	if _, _, err := instanceaccess.OpenWithIdentity(path, password); err != nil {
		t.Fatalf("busy refusal changed access: %v", err)
	}
}
