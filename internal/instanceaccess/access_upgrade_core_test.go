package instanceaccess

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func legacyUpgradeFixture(t *testing.T) (string, string, []byte, []byte, IdentityUpgradeCandidate) {
	t.Helper()
	path := accessPath(t)
	password := "a sufficiently long legacy password"
	key := bytes.Repeat([]byte{0x63}, 32)
	legacy, err := seal(key, password, ready, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	candidate, err := PrepareIdentityUpgrade(path, password)
	if err != nil {
		t.Fatal(err)
	}
	return path, password, key, legacy, candidate
}

func TestIdentityUpgradeCoreRejectsWrongKeyAndStaleRevision(t *testing.T) {
	path, password, _, legacy, candidate := legacyUpgradeFixture(t)
	wrongKey := candidate
	var err error
	wrongKey.EncryptedAccess, err = seal(bytes.Repeat([]byte{0x72}, 32), password, ready, candidate.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	writeCalled := false
	replaceSpy := func(string, []byte) error { writeCalled = true; return nil }
	if err := commitIdentityUpgradeLocked(path, password, wrongKey, replaceSpy, func(string) error { return nil }); !errors.Is(err, ErrInvalidUpgrade) || writeCalled {
		t.Fatalf("wrong-key candidate reached the writer: %v", err)
	}
	if err := os.WriteFile(path, append(append([]byte(nil), legacy...), ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := commitIdentityUpgradeLocked(path, password, candidate, replaceSpy, func(string) error { return nil }); !errors.Is(err, ErrStaleUpgrade) || writeCalled {
		t.Fatalf("stale candidate reached the writer: %v", err)
	}
}

func TestIdentityUpgradeCorePreservesPrewriteFailureAndReportsPostwriteUncertainty(t *testing.T) {
	path, password, key, legacy, candidate := legacyUpgradeFixture(t)
	prewrite := errors.New("simulated prewrite failure")
	err := commitIdentityUpgradeLocked(path, password, candidate, func(string, []byte) error { return prewrite },
		func(string) error { t.Fatal("sync after failed replace"); return nil })
	if !errors.Is(err, prewrite) {
		t.Fatalf("prewrite failure was hidden: %v", err)
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, legacy) {
		t.Fatalf("prewrite failure changed source: %v", err)
	}
	err = commitIdentityUpgradeLocked(path, password, candidate, replace, func(string) error {
		return errors.New("simulated directory sync failure")
	})
	if !errors.Is(err, ErrWriteUncertain) {
		t.Fatalf("postwrite failure was reported as definite: %v", err)
	}
	opened, id, err := OpenWithIdentity(path, password)
	if err != nil || !bytes.Equal(opened, key) || !bytes.Equal(id, candidate.InstallationID) {
		t.Fatalf("uncertain result lost key or ID: %v", err)
	}
}
