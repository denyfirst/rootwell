//go:build linux

package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestTheCheckedVaultNeedsAPrivateDirectory(t *testing.T) {
	key := testKey(t)
	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(loose, key); err == nil {
		t.Fatal("a vault was created in a directory others can read")
	}
	dir := privateDir(t)
	s, err := Create(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	put(t, s, "note", "a", "kept")
	_ = s.Close()
	if info, err := os.Stat(filepath.Join(dir, dbName)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode: %v %v", info.Mode(), err)
	}
	reopened, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()
	if err := os.Chmod(filepath.Join(dir, dbName), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, key); err == nil {
		t.Fatal("a database others can read was opened")
	}
	if err := os.Chmod(filepath.Join(dir, dbName), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, key); err == nil {
		t.Fatal("a vault in a group-readable directory was opened")
	}
}

func TestTheKeyFileIsPrivateAndNeverReplaced(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "instance.key")
	key := testKey(t)
	if err := WriteKeyFile(path, key); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", info.Mode(), err)
	}
	if err := WriteKeyFile(path, testKey(t)); err == nil {
		t.Fatal("the key file was replaced")
	}
	back, err := ReadKeyFile(path)
	if err != nil || !bytes.Equal(back, key) {
		t.Fatalf("read back: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(path); err == nil {
		t.Fatal("a key file others can read was accepted")
	}
	short := filepath.Join(dir, "short.key")
	long := filepath.Join(dir, "long.key")
	if err := os.WriteFile(short, key[:31], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(long, append(bytes.Clone(key), 0), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{short, long} {
		if _, err := ReadKeyFile(p); err == nil {
			t.Fatalf("%s was accepted as a key", filepath.Base(p))
		}
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(link); err == nil {
		t.Fatal("a symlinked key file was accepted")
	}
}
