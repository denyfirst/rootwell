package vault

import (
	"testing"

	bolt "go.etcd.io/bbolt"
)

// FuzzOpenSealedRecord stores arbitrary bytes where a sealed record belongs.
// Opening them must refuse, never panic, and never return plaintext: without
// the instance key no input is a record.
func FuzzOpenSealedRecord(f *testing.F) {
	key, err := NewInstanceKey()
	if err != nil {
		f.Fatal(err)
	}
	s, err := open(f.TempDir(), key, true)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = s.Close() })
	f.Add([]byte(`{"v":1,"r":1,"k":"","d":""}`))
	f.Add([]byte(`{"v":1,"r":1,"k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`))
	f.Add([]byte("not json"))
	f.Fuzz(func(t *testing.T, stored []byte) {
		if len(stored) == 0 {
			return
		}
		if err := s.db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("records/note"))
			if err != nil {
				return err
			}
			return b.Put([]byte("fuzz"), stored)
		}); err != nil {
			t.Fatal(err)
		}
		_ = s.View(func(tx *Tx) error {
			if plain, _, err := tx.Get("note", "fuzz"); err == nil {
				t.Fatalf("arbitrary bytes opened as a record: %q", plain)
			}
			return nil
		})
	})
}
