package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestRotationMovesEverySecretToTheNewKey(t *testing.T) {
	oldKey := testKey(t)
	s, dir := newTestVault(t, oldKey)
	put(t, s, "certificate", s.Index("certificate", "a"), "first")
	put(t, s, "certificate", s.Index("certificate", "a"), "first, changed")
	put(t, s, "account", s.Index("account", "ada"), "ada's record")
	idBefore, codesBefore := s.Index("account", "ada"), s.CodeKey()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A copy taken before the rotation, as an older backup would be.
	before := filepath.Join(t.TempDir(), "before")
	if err := os.Mkdir(before, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(before, dbName), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	s, err = open(dir, oldKey, false)
	if err != nil {
		t.Fatal(err)
	}
	newKey := testKey(t)
	if err := s.Rotate(newKey[:31]); err == nil {
		t.Fatal("a short key was taken")
	}
	if err := s.Rotate(newKey); err != nil {
		t.Fatal(err)
	}
	// The open store goes on with the new key at once.
	if got, revision, err := get(s, "certificate", s.Index("certificate", "a")); err != nil || got != "first, changed" || revision != 2 {
		t.Fatalf("after rotation: %q %d %v", got, revision, err)
	}
	put(t, s, "certificate", s.Index("certificate", "b"), "second")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if v, err := open(dir, oldKey, false); err == nil {
		_ = v.Close()
		t.Fatal("the old key still opens the rotated vault")
	}
	s, err = open(dir, newKey, false)
	if err != nil {
		t.Fatalf("the new key: %v", err)
	}
	defer s.Close()
	if s.Index("account", "ada") != idBefore || !bytes.Equal(s.CodeKey(), codesBefore) {
		t.Fatal("record IDs or the code key changed with the instance key")
	}
	for id, want := range map[string]string{s.Index("certificate", "a"): "first, changed", s.Index("certificate", "b"): "second"} {
		if got, _, err := get(s, "certificate", id); err != nil || got != want {
			t.Fatalf("record %s: %q %v", id, got, err)
		}
	}
	if got, _, err := get(s, "account", idBefore); err != nil || got != "ada's record" {
		t.Fatalf("account: %q %v", got, err)
	}
	// The copy from before opens with the old key only.
	if v, err := open(before, newKey, false); err == nil {
		_ = v.Close()
		t.Fatal("the new key opened a copy from before the rotation")
	}
	old, err := open(before, oldKey, false)
	if err != nil {
		t.Fatalf("the old copy with the old key: %v", err)
	}
	_ = old.Close()

	// A second rotation keeps working from the sealed keys.
	third := testKey(t)
	if err := s.Rotate(third); err != nil {
		t.Fatal(err)
	}
	if s.Index("account", "ada") != idBefore {
		t.Fatal("the second rotation changed record IDs")
	}
	if got, _, err := get(s, "account", idBefore); err != nil || got != "ada's record" {
		t.Fatalf("after a second rotation: %q %v", got, err)
	}
}

func TestADamagedSealedIndexKeyIsRefused(t *testing.T) {
	key := testKey(t)
	s, dir := newTestVault(t, key)
	next := testKey(t)
	if err := s.Rotate(next); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(filepath.Join(dir, dbName), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		m, err := readMeta(tx)
		if err != nil {
			return err
		}
		m.Index[len(m.Index)-1] ^= 1
		return putMeta(tx.Bucket(metaBucket), m)
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if v, err := open(dir, next, false); err == nil {
		_ = v.Close()
		t.Fatal("a vault with a damaged sealed index key opened")
	}
}

func TestABackupIsAWholeVaultThatOpensWithItsKey(t *testing.T) {
	key := testKey(t)
	s, _ := newTestVault(t, key)
	put(t, s, "certificate", s.Index("certificate", "a"), "kept in the backup")
	var copy bytes.Buffer
	n, err := s.Backup(&copy)
	if err != nil || n != int64(copy.Len()) || n == 0 {
		t.Fatalf("backup: %d bytes: %v", n, err)
	}
	if bytes.Contains(copy.Bytes(), []byte("kept in the backup")) || bytes.Contains(copy.Bytes(), key) {
		t.Fatal("the backup holds a plaintext or the instance key")
	}
	restored := t.TempDir()
	if err := os.WriteFile(filepath.Join(restored, dbName), copy.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := open(restored, testKey(t), false); err == nil {
		_ = v.Close()
		t.Fatal("another key opened the backup")
	}
	r, err := open(restored, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got, _, err := get(r, "certificate", r.Index("certificate", "a")); err != nil || got != "kept in the backup" {
		t.Fatalf("restored: %q %v", got, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Backup(&copy); err == nil {
		t.Fatal("a closed vault made a backup")
	}
}
