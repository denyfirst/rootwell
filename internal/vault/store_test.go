package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := NewInstanceKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// newTestVault reaches the store through the unchecked opener: the directory
// checks are Linux's (private_linux_test.go), the sealing is everyone's.
func newTestVault(t *testing.T, key []byte) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := open(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func put(t *testing.T, s *Store, kind, id, value string) {
	t.Helper()
	if err := s.Update(func(tx *Tx) error { return tx.Put(kind, id, []byte(value)) }); err != nil {
		t.Fatal(err)
	}
}

func get(s *Store, kind, id string) (string, uint64, error) {
	var value []byte
	var revision uint64
	err := s.View(func(tx *Tx) error {
		var err error
		value, revision, err = tx.Get(kind, id)
		return err
	})
	return string(value), revision, err
}

func TestRecordsRoundTripWithRevisionsAndGenerations(t *testing.T) {
	key := testKey(t)
	s, dir := newTestVault(t, key)
	put(t, s, "private-key", "a", "first")
	put(t, s, "private-key", "a", "second")
	put(t, s, "private-key", "b", "other")
	value, revision, err := get(s, "private-key", "a")
	if err != nil || value != "second" || revision != 2 {
		t.Fatalf("got %q revision %d: %v", value, revision, err)
	}
	var ids []string
	var generation uint64
	if err := s.View(func(tx *Tx) error {
		var err error
		if ids, err = tx.IDs("private-key"); err != nil {
			return err
		}
		generation, err = tx.Generation()
		return err
	}); err != nil || strings.Join(ids, ",") != "a,b" || generation != 3 {
		t.Fatalf("ids %v generation %d: %v", ids, generation, err)
	}
	if err := s.Update(func(tx *Tx) error { return tx.Delete("private-key", "a") }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := get(s, "private-key", "a"); !errors.Is(err, ErrMissing) {
		t.Fatalf("deleted record: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := open(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if value, _, err := get(reopened, "private-key", "b"); err != nil || value != "other" {
		t.Fatalf("after reopening: %q %v", value, err)
	}
}

func TestAFailedUpdateKeepsNothing(t *testing.T) {
	s, _ := newTestVault(t, testKey(t))
	defer s.Close()
	put(t, s, "note", "kept", "before")
	failure := errors.New("stop")
	if err := s.Update(func(tx *Tx) error {
		if err := tx.Put("note", "kept", []byte("after")); err != nil {
			return err
		}
		if err := tx.Put("note", "new", []byte("new")); err != nil {
			return err
		}
		return failure
	}); !errors.Is(err, failure) {
		t.Fatalf("update error: %v", err)
	}
	if value, revision, err := get(s, "note", "kept"); err != nil || value != "before" || revision != 1 {
		t.Fatalf("rolled back record: %q %d %v", value, revision, err)
	}
	if _, _, err := get(s, "note", "new"); !errors.Is(err, ErrMissing) {
		t.Fatalf("rolled back new record: %v", err)
	}
	_ = s.View(func(tx *Tx) error {
		if generation, _ := tx.Generation(); generation != 1 {
			t.Errorf("a failed update counted a generation: %d", generation)
		}
		return nil
	})
}

func TestAnotherKeyCannotOpenTheVault(t *testing.T) {
	key := testKey(t)
	s, dir := newTestVault(t, key)
	put(t, s, "private-key", "a", "secret")
	_ = s.Close()
	if _, err := open(dir, testKey(t), false); err == nil {
		t.Fatal("a different instance key opened the vault")
	}
	if _, err := open(dir, key[:31], false); err == nil {
		t.Fatal("a short key opened the vault")
	}
}

func TestCreateNeverReplacesAndOpenNeverCreates(t *testing.T) {
	key := testKey(t)
	s, dir := newTestVault(t, key)
	_ = s.Close()
	if _, err := open(dir, key, true); err == nil {
		t.Fatal("create replaced an existing vault")
	}
	if _, err := open(t.TempDir(), key, false); err == nil {
		t.Fatal("open created a vault")
	}
}

// rawEdit changes the database below the vault, as a thief or a broken disk
// could, then reopens it.
func rawEdit(t *testing.T, dir string, key []byte, edit func(tx *bolt.Tx) error) *Store {
	t.Helper()
	db, err := bolt.Open(filepath.Join(dir, dbName), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(edit); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := open(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestASealedRecordMovedOrChangedIsRefused(t *testing.T) {
	key := testKey(t)
	s, dir := newTestVault(t, key)
	put(t, s, "private-key", "a", "secret-a")
	put(t, s, "private-key", "b", "secret-b")
	put(t, s, "note", "a", "note-a")
	_ = s.Close()
	s = rawEdit(t, dir, key, func(tx *bolt.Tx) error {
		keys := tx.Bucket([]byte("records/private-key"))
		notes := tx.Bucket([]byte("records/note"))
		a := bytes.Clone(keys.Get([]byte("a")))
		if err := keys.Put([]byte("b"), a); err != nil { // another record's ciphertext
			return err
		}
		return notes.Put([]byte("a"), a) // another kind's ciphertext
	})
	defer s.Close()
	if _, _, err := get(s, "private-key", "b"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a record moved to another ID opened: %v", err)
	}
	if _, _, err := get(s, "note", "a"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a record moved to another kind opened: %v", err)
	}
	if value, _, err := get(s, "private-key", "a"); err != nil || value != "secret-a" {
		t.Fatalf("the untouched record: %q %v", value, err)
	}
}

func TestAChangedRevisionOrByteIsRefused(t *testing.T) {
	key := testKey(t)
	s, dir := newTestVault(t, key)
	put(t, s, "private-key", "a", "secret-a")
	put(t, s, "private-key", "b", "secret-b")
	_ = s.Close()
	s = rawEdit(t, dir, key, func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("records/private-key"))
		revised := bytes.Replace(b.Get([]byte("a")), []byte(`"r":1`), []byte(`"r":2`), 1)
		if err := b.Put([]byte("a"), revised); err != nil {
			return err
		}
		flipped := bytes.Clone(b.Get([]byte("b")))
		flipped[len(flipped)-10] ^= 0x01
		return b.Put([]byte("b"), flipped)
	})
	defer s.Close()
	for _, id := range []string{"a", "b"} {
		if _, _, err := get(s, "private-key", id); err == nil {
			t.Fatalf("record %s opened after being changed", id)
		}
	}
}

func TestNoPlaintextOrNameReachesTheDisk(t *testing.T) {
	key := testKey(t)
	s, dir := newTestVault(t, key)
	secret := "-----BEGIN PRIVATE KEY----- sentinel-secret-material"
	name := "AB:CD:EF:01:23:45:67:89:sentinel-fingerprint"
	id := s.Index("certificate", name)
	put(t, s, "private-key", id, secret)
	_ = s.Close()
	raw, err := os.ReadFile(filepath.Join(dir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{secret, "sentinel", name, hex.EncodeToString(key)} {
		if bytes.Contains(raw, []byte(leaked)) {
			t.Fatalf("the database file holds %q", leaked)
		}
	}
	sum := sha256.Sum256([]byte(name))
	if id == hex.EncodeToString(sum[:]) {
		t.Fatal("the record ID is the plain SHA-256 of its name")
	}
}

func TestIndexesDifferBetweenVaultsAndKinds(t *testing.T) {
	key := testKey(t)
	first, _ := newTestVault(t, key)
	defer first.Close()
	second, _ := newTestVault(t, key)
	defer second.Close()
	if first.Index("certificate", "x") == second.Index("certificate", "x") {
		t.Fatal("two vaults with one key share an index")
	}
	if first.Index("certificate", "x") == first.Index("private-key", "x") {
		t.Fatal("two kinds share an index")
	}
	once, again := first.Index("certificate", "x"), first.Index("certificate", "x")
	if once != again {
		t.Fatal("an index is not stable")
	}
}

func TestMalformedInputsAreRefused(t *testing.T) {
	s, _ := newTestVault(t, testKey(t))
	defer s.Close()
	for _, kind := range []string{"", "A", "x", "records/x", "key\x00", strings.Repeat("k", 33)} {
		if err := s.Update(func(tx *Tx) error { return tx.Put(kind, "id", []byte("v")) }); err == nil {
			t.Errorf("kind %q was accepted", kind)
		}
	}
	for _, id := range []string{"", "a/b", "a b", strings.Repeat("i", 129), "ü"} {
		if err := s.Update(func(tx *Tx) error { return tx.Put("note", id, []byte("v")) }); err == nil {
			t.Errorf("id %q was accepted", id)
		}
	}
	if err := s.Update(func(tx *Tx) error { return tx.Put("note", "big", make([]byte, maxPlaintext+1)) }); err == nil {
		t.Error("an oversized record was accepted")
	}
	if err := s.View(func(tx *Tx) error { return tx.Put("note", "ro", []byte("v")) }); err == nil {
		t.Error("a read transaction wrote")
	}
	_ = s.Close()
	if err := s.View(func(*Tx) error { return nil }); err == nil {
		t.Error("a closed vault answered")
	}
}

func TestRecoveryCodeRoundTripsAndRefusesDamage(t *testing.T) {
	key := testKey(t)
	code, err := RecoveryCode(key)
	if err != nil || !strings.HasPrefix(code, "RW1-") || len(strings.Split(code, "-")) != 13 {
		t.Fatalf("code %q: %v", code, err)
	}
	for _, typed := range []string{code, strings.ToLower(code), strings.ReplaceAll(code, "-", ""), "  " + strings.ReplaceAll(code, "-", " ") + "\n"} {
		back, err := ParseRecoveryCode(typed)
		if err != nil || !bytes.Equal(back, key) {
			t.Fatalf("typed %q did not restore the key: %v", typed, err)
		}
	}
	damaged := []byte(code)
	damaged[6] = map[bool]byte{true: 'B', false: 'A'}[damaged[6] == 'A']
	for _, bad := range []string{string(damaged), "KB1" + code[3:], code[:len(code)-1], code + "A", "", strings.Repeat("A", 300)} {
		if _, err := ParseRecoveryCode(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if _, err := RecoveryCode(key[:31]); err == nil {
		t.Error("a short key printed a code")
	}
}
