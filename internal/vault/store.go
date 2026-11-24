package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	dbName       = "rootwell.db"
	maxPlaintext = 1 << 20
	// A sealed record is JSON, so its two ciphertexts are base64: four bytes
	// for every three, plus the key, nonces, tags and field names.
	maxSealed   = maxPlaintext/3*4 + 4096
	metaVersion = 1
	sealVersion = 1
)

var (
	metaBucket = []byte("meta")
	metaKey    = []byte("store")
	kindName   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	recordID   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// Store is an open vault. Its methods are safe for concurrent use; bbolt
// serialises writers and lets readers run beside them.
type Store struct {
	mu       sync.RWMutex
	closed   bool
	root     *os.Root
	db       *bolt.DB
	instance string
	wrap     cipher.AEAD
	indexKey []byte
	codeKey  []byte
}

type storeMeta struct {
	Version    int    `json:"version"`
	Instance   string `json:"instance"`
	Check      []byte `json:"check"`
	Generation uint64 `json:"generation"`
	// After a key rotation, the index and code keys are kept sealed under
	// the new wrap key, so record IDs and code digests stay as they were.
	Index []byte `json:"index,omitempty"`
	Codes []byte `json:"codes,omitempty"`
}

type sealedRecord struct {
	Version  int    `json:"v"`
	Revision uint64 `json:"r"`
	Key      []byte `json:"k"`
	Data     []byte `json:"d"`
}

// Create makes a new vault in an existing private directory. It never
// replaces a database.
func Create(dir string, key []byte) (*Store, error) {
	if privateDirectory(dir, dbName) != nil {
		return nil, ErrRefused
	}
	return open(dir, key, true)
}

// Open opens the vault in a private directory with its instance key. A key
// that is not the one the vault was made with is refused.
func Open(dir string, key []byte) (*Store, error) {
	if privateDirectory(dir, dbName) != nil {
		return nil, ErrRefused
	}
	return open(dir, key, false)
}

func open(dir string, key []byte, create bool) (*Store, error) {
	if len(key) != KeySize {
		return nil, ErrRefused
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, ErrRefused
	}
	s := &Store{root: root}
	var stored storeMeta
	ok := false
	defer func() {
		if !ok {
			if s.db != nil {
				_ = s.db.Close()
			}
			_ = root.Close()
		}
	}()
	before, statErr := root.Lstat(dbName)
	switch {
	case create && statErr == nil, create && !os.IsNotExist(statErr):
		return nil, ErrRefused
	case !create && (statErr != nil || !before.Mode().IsRegular()):
		return nil, ErrRefused
	}
	s.db, err = bolt.Open(dbName, 0o600, &bolt.Options{Timeout: time.Second, MaxSize: 512 << 20,
		OpenFile: func(_ string, flags int, mode os.FileMode) (*os.File, error) {
			// The root keeps the file inside the pinned directory; also refuse a
			// symlink or an entry swapped since it was checked.
			if create {
				flags |= os.O_EXCL
			} else {
				flags &^= os.O_CREATE
			}
			f, err := root.OpenFile(dbName, flags, mode)
			if err != nil {
				return nil, err
			}
			now, nowErr := root.Lstat(dbName)
			actual, actualErr := f.Stat()
			if nowErr != nil || actualErr != nil || !now.Mode().IsRegular() || !os.SameFile(now, actual) ||
				(!create && !os.SameFile(before, actual)) {
				_ = f.Close()
				return nil, ErrRefused
			}
			return f, nil
		}})
	if err != nil {
		return nil, ErrRefused
	}
	if create {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, ErrRefused
		}
		s.instance = hex.EncodeToString(id[:])
	} else if err := s.db.View(func(tx *bolt.Tx) error {
		m, err := readMeta(tx)
		s.instance, stored = m.Instance, m
		return err
	}); err != nil {
		return nil, ErrRefused
	}
	if err := s.deriveKeys(key); err != nil {
		return nil, ErrRefused
	}
	if err := s.adoptSealedKeys(stored); err != nil {
		return nil, ErrRefused
	}
	check := s.check()
	if create {
		err = s.db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucket(metaBucket)
			if err != nil {
				return err
			}
			// Creating the vault is its first committed write, so a page never
			// holds generation zero, which means "never read".
			return putMeta(b, storeMeta{Version: metaVersion, Instance: s.instance, Check: check, Generation: 1})
		})
	} else {
		err = s.db.View(func(tx *bolt.Tx) error {
			m, err := readMeta(tx)
			if err != nil || !hmac.Equal(m.Check, check) {
				return ErrRefused
			}
			return nil
		})
	}
	if err != nil {
		return nil, ErrRefused
	}
	ok = true
	return s, nil
}

// deriveKeys makes each purpose's key from the instance key, salted by the
// instance ID, so two vaults never share a derived key.
func (s *Store) deriveKeys(key []byte) error {
	salt, err := hex.DecodeString(s.instance)
	if err != nil || len(salt) != 16 {
		return ErrRefused
	}
	wrapKey, err := hkdf.Key(sha256.New, key, salt, "rootwell/vault/v1/wrap", 32)
	if err != nil {
		return ErrRefused
	}
	defer clear(wrapKey)
	if s.wrap, err = randomGCM(wrapKey); err != nil {
		return ErrRefused
	}
	if s.indexKey, err = hkdf.Key(sha256.New, key, salt, "rootwell/vault/v1/index", 32); err != nil {
		return ErrRefused
	}
	if s.codeKey, err = hkdf.Key(sha256.New, key, salt, "rootwell/vault/v1/codes", 32); err != nil {
		return ErrRefused
	}
	return nil
}

// CodeKey is the key one-time codes are digested under: recovery codes and
// setup codes. It is derived apart from every other key, and a copy is
// returned for the caller to clear.
func (s *Store) CodeKey() []byte { return bytes.Clone(s.codeKey) }

// check is the vault's proof that a key is the one it was made with.
func (s *Store) check() []byte {
	h := hmac.New(sha256.New, s.indexKey)
	_, _ = h.Write([]byte("rootwell/vault/v1/check/" + s.instance))
	return h.Sum(nil)
}

func randomGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrRefused
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func readMeta(tx *bolt.Tx) (storeMeta, error) {
	var m storeMeta
	b := tx.Bucket(metaBucket)
	if b == nil || strictDecode(b.Get(metaKey), &m, 2048) != nil || m.Version != metaVersion ||
		len(m.Instance) != 32 || len(m.Check) != sha256.Size {
		return storeMeta{}, ErrRefused
	}
	if _, err := hex.DecodeString(m.Instance); err != nil {
		return storeMeta{}, ErrRefused
	}
	return m, nil
}

func putMeta(b *bolt.Bucket, m storeMeta) error {
	data, err := json.Marshal(m)
	if err != nil {
		return ErrRefused
	}
	return b.Put(metaKey, data)
}

func strictDecode(data []byte, v any, limit int) error {
	if len(data) == 0 || len(data) > limit {
		return ErrRefused
	}
	if err := json.Unmarshal(data, v); err != nil {
		return ErrRefused
	}
	return nil
}

// Close closes the database; later calls refuse.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.db.Close()
	if rootErr := s.root.Close(); err == nil {
		err = rootErr
	}
	return err
}

// Index turns a name, such as a certificate fingerprint, into a record ID
// that reveals nothing without the instance key (audit RW-12).
func (s *Store) Index(kind, name string) string {
	h := hmac.New(sha256.New, s.indexKey)
	_, _ = h.Write([]byte(kind))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(name))
	return hex.EncodeToString(h.Sum(nil))
}

// Tx is one transaction. Records opened in it are copies the caller owns.
type Tx struct {
	s        *Store
	tx       *bolt.Tx
	writable bool
}

// View runs fn in a read-only transaction.
func (s *Store) View(fn func(*Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrRefused
	}
	return s.db.View(func(tx *bolt.Tx) error { return fn(&Tx{s: s, tx: tx}) })
}

// Update runs fn in one write transaction and counts one generation. Nothing
// fn wrote is kept unless it returns nil.
func (s *Store) Update(fn func(*Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrRefused
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		m, err := readMeta(tx)
		if err != nil {
			return err
		}
		if err := fn(&Tx{s: s, tx: tx, writable: true}); err != nil {
			return err
		}
		m.Generation++
		return putMeta(tx.Bucket(metaBucket), m)
	})
}

// Generation counts the write transactions the vault has committed.
func (t *Tx) Generation() (uint64, error) {
	m, err := readMeta(t.tx)
	return m.Generation, err
}

func (t *Tx) aad(kind, id string, revision uint64) []byte {
	return fmt.Appendf(nil, "rootwell/vault/v1/%s/%s/%s/%d", t.s.instance, kind, id, revision)
}

// Put seals plaintext as the next revision of the record.
func (t *Tx) Put(kind, id string, plaintext []byte) error {
	if !t.writable || !kindName.MatchString(kind) || !recordID.MatchString(id) || len(plaintext) > maxPlaintext {
		return ErrRefused
	}
	b, err := t.tx.CreateBucketIfNotExists([]byte("records/" + kind))
	if err != nil {
		return ErrRefused
	}
	revision := uint64(1)
	if existing := b.Get([]byte(id)); existing != nil {
		var r sealedRecord
		if strictDecode(existing, &r, maxSealed) != nil || r.Revision == 0 || r.Revision == ^uint64(0) {
			return ErrRefused
		}
		revision = r.Revision + 1
	}
	var dataKey [32]byte
	if _, err := rand.Read(dataKey[:]); err != nil {
		return ErrRefused
	}
	defer clear(dataKey[:])
	aead, err := randomGCM(dataKey[:])
	if err != nil {
		return ErrRefused
	}
	aad := t.aad(kind, id, revision)
	// Both AEADs come from NewGCMWithRandomNonce, whose API takes a nil nonce
	// and generates and prefixes a random one itself.
	record := sealedRecord{
		Version:  sealVersion,
		Revision: revision,
		Key:      t.s.wrap.Seal(nil, nil, dataKey[:], append([]byte("wrap/"), aad...)), // #nosec G407 -- random-nonce GCM API, never a fixed IV.
		Data:     aead.Seal(nil, nil, plaintext, append([]byte("data/"), aad...)),      // #nosec G407 -- random-nonce GCM API, never a fixed IV.
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return ErrRefused
	}
	return b.Put([]byte(id), encoded)
}

// ErrMissing says a record does not exist, which callers may tell apart from
// a refusal.
var ErrMissing = errors.New("vault record does not exist")

// Get opens a record and returns its plaintext and revision.
func (t *Tx) Get(kind, id string) ([]byte, uint64, error) {
	if !kindName.MatchString(kind) || !recordID.MatchString(id) {
		return nil, 0, ErrRefused
	}
	b := t.tx.Bucket([]byte("records/" + kind))
	if b == nil {
		return nil, 0, ErrMissing
	}
	encoded := b.Get([]byte(id))
	if encoded == nil {
		return nil, 0, ErrMissing
	}
	var r sealedRecord
	if strictDecode(encoded, &r, maxSealed) != nil || r.Version != sealVersion || r.Revision == 0 ||
		len(r.Key) != 12+32+16 || len(r.Data) < 12+16 {
		return nil, 0, ErrRefused
	}
	aad := t.aad(kind, id, r.Revision)
	dataKey, err := t.s.wrap.Open(nil, nil, r.Key, append([]byte("wrap/"), aad...))
	if err != nil {
		return nil, 0, ErrRefused
	}
	defer clear(dataKey)
	aead, err := randomGCM(dataKey)
	if err != nil {
		return nil, 0, ErrRefused
	}
	plaintext, err := aead.Open(nil, nil, r.Data, append([]byte("data/"), aad...))
	if err != nil {
		return nil, 0, ErrRefused
	}
	return plaintext, r.Revision, nil
}

// Delete removes a record. A missing record is not an error.
func (t *Tx) Delete(kind, id string) error {
	if !t.writable || !kindName.MatchString(kind) || !recordID.MatchString(id) {
		return ErrRefused
	}
	b := t.tx.Bucket([]byte("records/" + kind))
	if b == nil {
		return nil
	}
	return b.Delete([]byte(id))
}

// IDs lists a kind's record IDs in byte order.
func (t *Tx) IDs(kind string) ([]string, error) {
	if !kindName.MatchString(kind) {
		return nil, ErrRefused
	}
	b := t.tx.Bucket([]byte("records/" + kind))
	if b == nil {
		return nil, nil
	}
	var ids []string
	err := b.ForEach(func(k, _ []byte) error {
		ids = append(ids, string(k))
		return nil
	})
	return ids, err
}

func (s *Store) metaAAD(name string) []byte {
	return []byte("rootwell/vault/v1/" + s.instance + "/meta/" + name)
}

// adoptSealedKeys takes the index and code keys from a vault that has had
// its instance key rotated: they are sealed in the meta record under the
// current wrap key. A vault never rotated derives them from its key.
func (s *Store) adoptSealedKeys(m storeMeta) error {
	if len(m.Index) == 0 && len(m.Codes) == 0 {
		return nil
	}
	index, err := s.wrap.Open(nil, nil, m.Index, s.metaAAD("index"))
	if err != nil || len(index) != 32 {
		return ErrRefused
	}
	codes, err := s.wrap.Open(nil, nil, m.Codes, s.metaAAD("codes"))
	if err != nil || len(codes) != 32 {
		clear(index)
		return ErrRefused
	}
	clear(s.indexKey)
	clear(s.codeKey)
	s.indexKey, s.codeKey = index, codes
	return nil
}

// Rotate moves the vault to a new instance key in one transaction: every
// record's data key is wrapped again under the new key, and the index and
// code keys are sealed under it, so records keep their IDs and one-time codes
// their digests. After it commits, the old key opens nothing in this file; a
// copy made before still opens with the old key only (audit RW-04).
func (s *Store) Rotate(newKey []byte) error {
	if len(newKey) != KeySize {
		return ErrRefused
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrRefused
	}
	salt, err := hex.DecodeString(s.instance)
	if err != nil {
		return ErrRefused
	}
	wrapKey, err := hkdf.Key(sha256.New, newKey, salt, "rootwell/vault/v1/wrap", 32)
	if err != nil {
		return ErrRefused
	}
	defer clear(wrapKey)
	next, err := randomGCM(wrapKey)
	if err != nil {
		return ErrRefused
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		m, err := readMeta(tx)
		if err != nil {
			return err
		}
		err = tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			kind, ok := strings.CutPrefix(string(name), "records/")
			if !ok {
				return nil
			}
			type entry struct{ id, value []byte }
			var entries []entry
			if err := b.ForEach(func(k, v []byte) error {
				entries = append(entries, entry{bytes.Clone(k), bytes.Clone(v)})
				return nil
			}); err != nil {
				return err
			}
			for _, e := range entries {
				var r sealedRecord
				if strictDecode(e.value, &r, maxSealed) != nil || r.Version != sealVersion || r.Revision == 0 {
					return ErrRefused
				}
				aad := append([]byte("wrap/"), fmt.Appendf(nil, "rootwell/vault/v1/%s/%s/%s/%d", s.instance, kind, e.id, r.Revision)...)
				dataKey, err := s.wrap.Open(nil, nil, r.Key, aad)
				if err != nil {
					return ErrRefused
				}
				r.Key = next.Seal(nil, nil, dataKey, aad) // #nosec G407 -- random-nonce GCM API, never a fixed IV.
				clear(dataKey)
				encoded, err := json.Marshal(r)
				if err != nil {
					return ErrRefused
				}
				if err := b.Put(e.id, encoded); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		m.Index = next.Seal(nil, nil, s.indexKey, s.metaAAD("index")) // #nosec G407 -- random-nonce GCM API, never a fixed IV.
		m.Codes = next.Seal(nil, nil, s.codeKey, s.metaAAD("codes"))  // #nosec G407 -- random-nonce GCM API, never a fixed IV.
		m.Generation++
		return putMeta(tx.Bucket(metaBucket), m)
	})
	if err != nil {
		return ErrRefused
	}
	s.wrap = next
	return nil
}

// Backup writes a consistent copy of the whole vault to w, in one read
// transaction, while the service keeps running. The copy holds no instance
// key: it opens only with the key the vault had when it was made.
func (s *Store) Backup(w io.Writer) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, ErrRefused
	}
	var n int64
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		n, err = tx.WriteTo(w)
		return err
	})
	return n, err
}
