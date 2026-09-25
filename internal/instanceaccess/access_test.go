package instanceaccess

import (
	"bytes"
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
	if err := ChangeInitialPassword(path, initial, initial); err == nil {
		t.Fatal("unchanged initial password accepted")
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
