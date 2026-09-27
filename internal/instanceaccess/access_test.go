package instanceaccess

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func accessPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "access.json")
}

func TestPrepareIdentityUpgradePreservesKeyWithoutChangingSource(t *testing.T) {
	const password = "a sufficiently long legacy password"
	path := accessPath(t)
	key := bytes.Repeat([]byte{0x41}, 32)
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
	if candidate.ExpectedRevision != sha256.Sum256(legacy) || len(candidate.InstallationID) != 16 ||
		bytes.Equal(candidate.EncryptedAccess, legacy) || bytes.Contains(candidate.EncryptedAccess, key) ||
		bytes.Contains(candidate.EncryptedAccess, []byte(password)) {
		t.Fatal("upgrade candidate is unbound, unencrypted, or missing identity")
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, legacy) {
		t.Fatalf("preparation changed the original file: %v", err)
	}
	if _, _, err := OpenWithIdentity(path, password); !errors.Is(err, ErrIdentityMissing) {
		t.Fatalf("preparation silently upgraded original: %v", err)
	}
	staged := accessPath(t)
	if err := os.WriteFile(staged, candidate.EncryptedAccess, 0o600); err != nil {
		t.Fatal(err)
	}
	opened, id, err := OpenWithIdentity(staged, password)
	if err != nil || !bytes.Equal(opened, key) || !bytes.Equal(id, candidate.InstallationID) {
		t.Fatalf("candidate lost the key or identity: %v", err)
	}
	again, err := PrepareIdentityUpgrade(path, password)
	if err != nil || bytes.Equal(candidate.InstallationID, again.InstallationID) {
		t.Fatalf("independent preparations reused identity: %v", err)
	}
}

func TestPrepareIdentityUpgradeRefusesWrongStateAndUnsafeInput(t *testing.T) {
	const password = "a sufficiently long legacy password"
	path := accessPath(t)
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, state := range []string{setup, ready} {
		legacy, err := seal(key, password, state, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, legacy, 0o600); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := PrepareIdentityUpgrade(path, "incorrect legacy password")
		if !errors.Is(err, ErrWrongPassword) || !emptyUpgrade(candidate) {
			t.Fatalf("wrong password prepared identity: %v", err)
		}
		if state == setup {
			candidate, err = PrepareIdentityUpgrade(path, password)
			if !errors.Is(err, ErrChangeRequired) || !emptyUpgrade(candidate) {
				t.Fatalf("setup password prepared identity: %v", err)
			}
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("refused preparation changed file: %v", err)
		}
	}
	v2path := accessPath(t)
	if err := Create(v2path, password); err != nil {
		t.Fatal(err)
	}
	if err := ChangeInitialPassword(v2path, password, "a sufficiently long activated password"); err != nil {
		t.Fatal(err)
	}
	candidate, err := PrepareIdentityUpgrade(v2path, "a sufficiently long activated password")
	if !errors.Is(err, ErrIdentityExists) || !emptyUpgrade(candidate) {
		t.Fatalf("v2 installation prepared another identity: %v", err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate, err = PrepareIdentityUpgrade(path, password)
	if !errors.Is(err, ErrInvalidAccess) || !emptyUpgrade(candidate) {
		t.Fatalf("malformed file prepared identity: %v", err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate, err = PrepareIdentityUpgrade(path, password)
	if !errors.Is(err, ErrInvalidAccess) || !emptyUpgrade(candidate) {
		t.Fatalf("oversized file prepared identity: %v", err)
	}
	link := filepath.Join(t.TempDir(), "access-link")
	if err := os.Symlink(v2path, link); err == nil {
		candidate, err = PrepareIdentityUpgrade(link, "a sufficiently long activated password")
		if !errors.Is(err, ErrInvalidAccess) || !emptyUpgrade(candidate) {
			t.Fatalf("symlink prepared identity: %v", err)
		}
	}
}

func emptyUpgrade(candidate IdentityUpgradeCandidate) bool {
	return candidate.ExpectedRevision == [32]byte{} && len(candidate.EncryptedAccess) == 0 && len(candidate.InstallationID) == 0
}

func TestPostReplaceSyncFailureReportsUncertainOutcome(t *testing.T) {
	const initial = "a sufficiently long initial password"
	const next = "a sufficiently long changed password"
	path := accessPath(t)
	if err := Create(path, initial); err != nil {
		t.Fatal(err)
	}
	err := changeLockedWithSync(path, initial, next, setup, func(string) error {
		return errors.New("simulated directory sync failure")
	})
	if !errors.Is(err, ErrWriteUncertain) {
		t.Fatalf("post-replacement failure reported a definite outcome: %v", err)
	}
	if key, err := Open(path, next); err != nil || len(key) != 32 {
		t.Fatalf("uncertain outcome hid the new, valid access file: %v", err)
	}
}

func TestV2IdentityIsUniqueAuthenticatedAndSurvivesPasswordChanges(t *testing.T) {
	const initial = "an initial password for this test"
	const activated = "an activated password for this test"
	const rotated = "a rotated password for this test"
	path := accessPath(t)
	other := accessPath(t)
	for _, name := range []string{path, other} {
		if err := Create(name, initial); err != nil {
			t.Fatal(err)
		}
	}
	if key, id, err := OpenWithIdentity(path, initial); !errors.Is(err, ErrChangeRequired) || key != nil || id != nil {
		t.Fatalf("setup leaked key or identity: %v", err)
	}
	if err := ChangeInitialPassword(path, initial, activated); err != nil {
		t.Fatal(err)
	}
	if err := ChangeInitialPassword(other, initial, activated); err != nil {
		t.Fatal(err)
	}
	key, id, err := OpenWithIdentity(path, activated)
	if err != nil || len(key) != 32 || len(id) != 16 {
		t.Fatalf("v2 identity not opened: %v", err)
	}
	_, otherID, err := OpenWithIdentity(other, activated)
	if err != nil || bytes.Equal(id, otherID) {
		t.Fatalf("installation identities are not independent: %v", err)
	}
	if err := ChangePassword(path, activated, rotated); err != nil {
		t.Fatal(err)
	}
	rotatedKey, rotatedID, err := OpenWithIdentity(path, rotated)
	if err != nil || !bytes.Equal(key, rotatedKey) || !bytes.Equal(id, rotatedID) {
		t.Fatalf("rotation changed the data key or identity: %v", err)
	}
	if key, id, err := OpenWithIdentity(path, activated); !errors.Is(err, ErrWrongPassword) || key != nil || id != nil {
		t.Fatalf("old password opened identity: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ChangePassword(path, "wrong current password", "another replacement password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password changed access: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed rotation changed access: %v", err)
	}

	var e envelope
	if err := json.Unmarshal(before, &e); err != nil {
		t.Fatal(err)
	}
	if e.Version != 2 || !bytes.Equal(e.InstallationID, id) {
		t.Fatal("access file lacks its v2 identity")
	}
	e.InstallationID[0] ^= 1
	tampered, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if key, id, err := OpenWithIdentity(path, rotated); err == nil || key != nil || id != nil {
		t.Fatalf("tampered identity opened: %v", err)
	}
}

func TestLegacyV1CanStillOpenButCannotClaimAnIdentity(t *testing.T) {
	path := accessPath(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	const old = "a sufficiently long old password"
	const next = "a sufficiently long new password"
	body, err := seal(key, old, ready, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(path, old)
	if err != nil || !bytes.Equal(key, opened) {
		t.Fatalf("v1 access no longer opens: %v", err)
	}
	if got, id, err := OpenWithIdentity(path, old); !errors.Is(err, ErrIdentityMissing) || got != nil || id != nil {
		t.Fatalf("v1 claimed an identity: %v", err)
	}
	if err := ChangePassword(path, old, next); err != nil {
		t.Fatal(err)
	}
	opened, err = Open(path, next)
	if err != nil || !bytes.Equal(key, opened) {
		t.Fatalf("v1 rotation changed key: %v", err)
	}
	if got, id, err := OpenWithIdentity(path, next); !errors.Is(err, ErrIdentityMissing) || got != nil || id != nil {
		t.Fatalf("v1 rotation silently enrolled identity: %v", err)
	}
}

func TestV2RejectsMalformedIdentityAndVersion(t *testing.T) {
	const password = "an initial password for this test"
	path := accessPath(t)
	if err := Create(path, password); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e envelope
	if err := json.Unmarshal(original, &e); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*envelope){
		func(e *envelope) { e.Version = 3 },
		func(e *envelope) { e.Version = 1 },
		func(e *envelope) { e.InstallationID = nil },
		func(e *envelope) { e.InstallationID = []byte{1} },
	} {
		changed := e
		changed.InstallationID = append([]byte(nil), e.InstallationID...)
		edit(&changed)
		body, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if key, id, err := OpenWithIdentity(path, password); err == nil || key != nil || id != nil {
			t.Fatalf("malformed v2 identity opened: %v", err)
		}
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if setup, err := Authenticate(path, password); err != nil || !setup {
		t.Fatalf("original v2 file did not survive malformed-input test: %v", err)
	}
}

func TestInitialPasswordRequiresChangeBeforeDataKeyIsAvailable(t *testing.T) {
	path := accessPath(t)
	initial, err := GenerateInitialPassword()
	if err != nil {
		t.Fatal(err)
	}
	if err := Create(path, initial); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, initial); !errors.Is(err, ErrChangeRequired) {
		t.Fatalf("initial password opened the data key: %v", err)
	}
	if changeRequired, err := Authenticate(path, initial); err != nil || !changeRequired {
		t.Fatalf("setup authentication did not require change: %v", err)
	}
	if _, err := Open(path, "not-the-password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := ChangeInitialPassword(path, initial, "correct horse battery staple 2026"); err != nil {
		t.Fatal(err)
	}
	key, err := Open(path, "correct horse battery staple 2026")
	if err != nil || len(key) != 32 {
		t.Fatalf("changed password did not open data key: %v", err)
	}
	if _, err := Open(path, initial); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("initial password still works: %v", err)
	}
	if changeRequired, err := Authenticate(path, "correct horse battery staple 2026"); err != nil || changeRequired {
		t.Fatalf("activated authentication failed: %v", err)
	}
	if err := ChangeInitialPassword(path, initial, "another sufficiently long password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("initial password changed twice: %v", err)
	}
	if err := ChangeInitialPassword(path, "correct horse battery staple 2026", "another sufficiently long password"); err == nil {
		t.Fatal("setup operation accepted after activation")
	}
	if err := ChangePassword(path, "correct horse battery staple 2026", "a different sufficiently long password"); err != nil {
		t.Fatal(err)
	}
	keyAfter, err := Open(path, "a different sufficiently long password")
	if err != nil || !bytes.Equal(key, keyAfter) {
		t.Fatalf("rotation changed or lost the data key: %v", err)
	}
}

func TestInitialPasswordIsUniqueAndNotStoredInPlaintext(t *testing.T) {
	a, err := GenerateInitialPassword()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateInitialPassword()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(strings.ReplaceAll(a, "-", "")) != 32 {
		t.Fatal("initial password lacks expected random encoding")
	}
	path := accessPath(t)
	if err := Create(path, a); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(a)) {
		t.Fatal("initial password stored in access file")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("access file permission: %v", err)
		}
	}
	if err := Create(path, b); err == nil {
		t.Fatal("existing installation overwritten")
	}
	if _, err := Open(path, a); !errors.Is(err, ErrChangeRequired) {
		t.Fatal("failed create changed existing installation")
	}
}

func TestFailedChangesKeepInitialPasswordAndRejectWeakReplacement(t *testing.T) {
	path := accessPath(t)
	initial := "initial password kept locally"
	if err := Create(path, initial); err != nil {
		t.Fatal(err)
	}
	if err := ChangeInitialPassword(path, "wrong initial password", "a long replacement password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong current password: %v", err)
	}
	if err := ChangeInitialPassword(path, initial, "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak replacement: %v", err)
	}
	if _, err := Open(path, initial); !errors.Is(err, ErrChangeRequired) {
		t.Fatalf("failed change activated installation: %v", err)
	}
	if err := ChangeInitialPassword(path, initial, initial); !errors.Is(err, ErrPasswordUnchanged) {
		t.Fatalf("unchanged initial password accepted: %v", err)
	}
	if err := ChangeInitialPassword(path, initial, strings.Repeat("x", maxPass+1)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("oversized replacement accepted: %v", err)
	}
}

func TestMalformedAndUnsafeAccessFilesFailClosed(t *testing.T) {
	path := accessPath(t)
	if err := Create(path, "a sufficiently long initial password"); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{
		[]byte("{"),
		bytes.Repeat([]byte("x"), maxFile+1),
		bytes.Replace(original, []byte(`"rounds":600000`), []byte(`"rounds":1`), 1),
		bytes.Replace(original, []byte(`"state":"change-required"`), []byte(`"state":"ready"`), 1),
		append(append([]byte{}, original...), []byte("{}")...),
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, "a sufficiently long initial password"); err == nil {
			t.Fatalf("malformed access file accepted: %q", body[:min(len(body), 80)])
		}
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, "a sufficiently long initial password"); !errors.Is(err, ErrInvalidAccess) {
			t.Fatalf("world-readable access file accepted: %v", err)
		}
	}
}

func TestSymlinkAndErrorsDoNotExposeConfiguredPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private-operator-location")
	if err := Create(path, "a sufficiently long initial password"); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err == nil {
		if _, err := Open(link, "a sufficiently long initial password"); !errors.Is(err, ErrInvalidAccess) {
			t.Fatalf("symlink opened: %v", err)
		}
	}
	if err := Create(path, "a different sufficiently long password"); err == nil || strings.Contains(err.Error(), path) {
		t.Fatalf("create failure exposed path or overwrote file: %v", err)
	}
}
