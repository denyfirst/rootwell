//go:build linux

package instanceaccess

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestLinuxIdentityUpgradeCommitsOnlyMatchingReadyV1(t *testing.T) {
	path, password, key, _, candidate := legacyUpgradeFixture(t)
	if err := CommitIdentityUpgrade(path, password, candidate); err != nil {
		t.Fatal(err)
	}
	opened, id, err := OpenWithIdentity(path, password)
	if err != nil || !bytes.Equal(opened, key) || !bytes.Equal(id, candidate.InstallationID) {
		t.Fatalf("committed upgrade changed the key or identity: %v", err)
	}
	if err := CommitIdentityUpgrade(path, password, candidate); !errors.Is(err, ErrStaleUpgrade) {
		t.Fatalf("replayed candidate was not refused: %v", err)
	}
}

func TestLinuxIdentityUpgradeRejectsStaleCandidate(t *testing.T) {
	path, password, key, _, candidate := legacyUpgradeFixture(t)
	const next = "a different sufficiently long password"
	if err := ChangePassword(path, password, next); err != nil {
		t.Fatal(err)
	}
	if err := CommitIdentityUpgrade(path, password, candidate); !errors.Is(err, ErrStaleUpgrade) {
		t.Fatalf("stale candidate installed: %v", err)
	}
	opened, err := Open(path, next)
	if err != nil || !bytes.Equal(opened, key) {
		t.Fatalf("stale upgrade damaged current access: %v", err)
	}
}

func TestLinuxIdentityUpgradeRejectsTamperingWrongKeyAndBusyLock(t *testing.T) {
	path, password, key, legacy, candidate := legacyUpgradeFixture(t)
	variants := []IdentityUpgradeCandidate{}
	wrongID := candidate
	wrongID.InstallationID = bytes.Repeat([]byte{0x55}, 16)
	variants = append(variants, wrongID)
	wrongKey := candidate
	var err error
	wrongKey.EncryptedAccess, err = seal(bytes.Repeat([]byte{0x66}, 32), password, ready, candidate.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	variants = append(variants, wrongKey)
	setupCandidate := candidate
	setupCandidate.EncryptedAccess, err = seal(key, password, setup, candidate.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	variants = append(variants, setupCandidate)
	malformed := candidate
	malformed.EncryptedAccess = []byte("{")
	variants = append(variants, malformed)
	for _, variant := range variants {
		if err := CommitIdentityUpgrade(path, password, variant); !errors.Is(err, ErrInvalidUpgrade) {
			t.Fatalf("invalid candidate installed: %v", err)
		}
	}
	if err := CommitIdentityUpgrade(path, "incorrect legacy password", candidate); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password installed candidate: %v", err)
	}
	if err := withAccessWriteLock(path, func() error {
		if err := CommitIdentityUpgrade(path, password, candidate); !errors.Is(err, ErrAccessBusy) {
			t.Fatalf("busy writer installed candidate: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, legacy) {
		t.Fatalf("rejected upgrade mutated access: %v", err)
	}
}

func TestLinuxIdentityUpgradeFaultsPreserveOrReportUncertain(t *testing.T) {
	path, password, key, legacy, candidate := legacyUpgradeFixture(t)
	replacementFailed := errors.New("simulated pre-rename failure")
	err := commitIdentityUpgradeLocked(path, password, candidate, func(string, []byte) error {
		return replacementFailed
	}, func(string) error { t.Fatal("sync after failed replacement"); return nil })
	if !errors.Is(err, replacementFailed) {
		t.Fatalf("pre-rename failure was not returned: %v", err)
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, legacy) {
		t.Fatalf("pre-rename failure changed access: %v", err)
	}
	err = commitIdentityUpgradeLocked(path, password, candidate, replace, func(string) error {
		return errors.New("simulated directory sync failure")
	})
	if !errors.Is(err, ErrWriteUncertain) {
		t.Fatalf("post-rename failure reported definite result: %v", err)
	}
	opened, id, err := OpenWithIdentity(path, password)
	if err != nil || !bytes.Equal(opened, key) || !bytes.Equal(id, candidate.InstallationID) {
		t.Fatalf("uncertain upgrade produced an invalid access file: %v", err)
	}
}
