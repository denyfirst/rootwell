//go:build linux

package secretfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteNewPrivateAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.p12")
	data := []byte("generated test secret container")
	if err := WriteNew(path, data); err != nil {
		t.Fatalf("WriteNew: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("written bytes differ")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("output permission: %v, %v", info, err)
	}
	if err := WriteNew(path, []byte("replacement")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("overwrite accepted: %v", err)
	}
	got, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("existing secret changed")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".rootwell-secret-*")); len(matches) != 0 {
		t.Fatalf("staging remains: %v", matches)
	}
}

func TestWriteNewRejectsUnsafeDirectoryAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.p12")
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(path, []byte("secret")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("public directory accepted: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("output after refusal: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(path, []byte("secret")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("symlink accepted: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "keep" {
		t.Fatal("symlink target changed")
	}
	linkedDir := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(dir, linkedDir); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(filepath.Join(linkedDir, "another.p12"), []byte("secret")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("symlink directory accepted: %v", err)
	}
}
