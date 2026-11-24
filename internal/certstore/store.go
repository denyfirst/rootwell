// Package certstore keeps the Certificates page's list in the vault.
//
// Each certificate is one sealed record: its public certificates and the
// notes people add. A private key, when there is one, is a record of its own,
// opened only to hand it out, so reading the list never opens a key (audit
// RW-11). Every change names the generation it was made against, so a page
// that shows an older list cannot overwrite a newer one. The generation is the
// list's own count, kept in a record of its own: sign-in writes to the same
// vault, and must not make an open Certificates page out of date.
package certstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/publicinventory"
	"github.com/denyfirst/rootwell/internal/vault"
)

const (
	kindCertificate = "certificate"
	kindKey         = "certificate-key"
	kindList        = "certificate-list"
	// MaxCertificates is how many certificates the list holds.
	MaxCertificates = 500
	maxKeyBytes     = 64 << 10
)

var (
	// ErrStale says the list changed since the page read it.
	ErrStale = errors.New("the list changed since it was read")
	// ErrNotFound says the certificate is not in the list.
	ErrNotFound = errors.New("the certificate is not in the list")
	// ErrKeyExists says a key is already saved; a key is never replaced.
	ErrKeyExists = errors.New("a private key is already saved with this certificate")
	// ErrKeyNeedsCode says the certificate has a saved key, and deleting it
	// needs a fresh phone code (ADR 0088).
	ErrKeyNeedsCode = errors.New("deleting a saved key needs a fresh code")
	// ErrFull says the list holds MaxCertificates already.
	ErrFull = errors.New("the list is full")
	// ErrUnavailable hides a vault refusal: a damaged or unreadable record.
	ErrUnavailable = errors.New("the stored list could not be read")
)

// LocationChange names what happens to one place a certificate is used.
type LocationChange int

const (
	// Rename replaces one place with a new name.
	Rename LocationChange = iota + 1
	// Remove takes one place off the certificate.
	Remove
)

// Store reads and changes the list. It is safe for concurrent use.
type Store struct {
	v   *vault.Store
	now func() time.Time
}

// New uses an open vault.
func New(v *vault.Store) *Store { return &Store{v: v, now: time.Now} }

type certificateRecord struct {
	Fingerprint string   `json:"fingerprint"`
	Added       uint64   `json:"added"`
	AddedAt     string   `json:"added_at"`
	DER         []byte   `json:"der"`
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	DNSNames    []string `json:"dns_names,omitempty"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	Owner       string   `json:"owner,omitempty"`
	Locations   []string `json:"locations,omitempty"`
	Bundle      [][]byte `json:"bundle"`
	Issuers     [][]byte `json:"issuers,omitempty"`
	HasKey      bool     `json:"has_key,omitempty"`
	KeyStatus   string   `json:"key_status"`
}

type keyRecord struct {
	Key []byte `json:"key"`
	// A key that does not match its certificate is kept only when the person
	// said so; the acknowledgement is sealed with the key it covers.
	MismatchAcknowledged bool `json:"mismatch_acknowledged,omitempty"`
}

// listRecord counts the changes made to the list. A vault without one has
// never changed the list, and is at generation 1.
type listRecord struct {
	Generation uint64 `json:"generation"`
}

func (c certificateRecord) record() publicinventory.Record {
	r := publicinventory.Record{
		Fingerprint: c.Fingerprint, ImportGeneration: c.Added, ImportedAt: c.AddedAt,
		DER: bytes.Clone(c.DER), Subject: c.Subject, Issuer: c.Issuer,
		DNSNames: slices.Clone(c.DNSNames), NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		Owner: c.Owner, Locations: slices.Clone(c.Locations),
		HasPrivateKey: c.HasKey, KeyStatus: c.KeyStatus,
		BundleDER: cloneDER(c.Bundle), IssuerDER: cloneDER(c.Issuers),
	}
	if len(r.Locations) > 0 {
		r.Location = r.Locations[0]
	}
	return r
}

func cloneDER(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = bytes.Clone(in[i])
	}
	return out
}

// List returns every certificate, oldest first, and the generation the list
// was read at. No key is opened.
func (s *Store) List() ([]publicinventory.Record, uint64, error) {
	var records []publicinventory.Record
	var generation uint64
	err := s.v.View(func(t *vault.Tx) error {
		var err error
		if generation, err = s.generation(t); err != nil {
			return err
		}
		ids, err := t.IDs(kindCertificate)
		if err != nil {
			return ErrUnavailable
		}
		stored := make([]certificateRecord, 0, len(ids))
		for _, id := range ids {
			c, err := s.readID(t, id)
			if err != nil {
				return err
			}
			stored = append(stored, c)
		}
		slices.SortFunc(stored, func(a, b certificateRecord) int {
			if a.Added != b.Added {
				if a.Added < b.Added {
					return -1
				}
				return 1
			}
			return bytes.Compare([]byte(a.Fingerprint), []byte(b.Fingerprint))
		})
		records = make([]publicinventory.Record, 0, len(stored))
		for _, c := range stored {
			records = append(records, c.record())
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return records, generation, nil
}

// readID opens one certificate record and checks it sits under its own
// fingerprint's index, so a record copied to another slot is refused.
func (s *Store) readID(t *vault.Tx, id string) (certificateRecord, error) {
	plain, _, err := t.Get(kindCertificate, id)
	if err != nil {
		if errors.Is(err, vault.ErrMissing) {
			return certificateRecord{}, ErrNotFound
		}
		return certificateRecord{}, ErrUnavailable
	}
	var c certificateRecord
	if strictJSON(plain, &c) != nil || !publicinventory.ValidFingerprint(c.Fingerprint) ||
		s.v.Index(kindCertificate, c.Fingerprint) != id || len(c.DER) == 0 || len(c.Bundle) == 0 ||
		!bytes.Equal(c.Bundle[0], c.DER) || c.Added == 0 {
		return certificateRecord{}, ErrUnavailable
	}
	return c, nil
}

func (s *Store) read(t *vault.Tx, fingerprint string) (certificateRecord, string, error) {
	if !publicinventory.ValidFingerprint(fingerprint) {
		return certificateRecord{}, "", ErrNotFound
	}
	id := s.v.Index(kindCertificate, fingerprint)
	c, err := s.readID(t, id)
	return c, id, err
}

func put(t *vault.Tx, kind, id string, value any) error {
	plain, err := json.Marshal(value) // #nosec G117 -- sealed by the vault at once; key bytes are cleared below.
	defer clear(plain)
	if err != nil || t.Put(kind, id, plain) != nil {
		return ErrUnavailable
	}
	return nil
}

func strictJSON(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data")
	}
	return nil
}

// generation reads the list's change count.
func (s *Store) generation(t *vault.Tx) (uint64, error) {
	plain, _, err := t.Get(kindList, s.v.Index(kindList, "list"))
	defer clear(plain)
	if errors.Is(err, vault.ErrMissing) {
		return 1, nil
	}
	var l listRecord
	if err != nil || strictJSON(plain, &l) != nil || l.Generation < 2 {
		return 0, ErrUnavailable
	}
	return l.Generation, nil
}

// fresh refuses a change made against any generation but the current one.
func (s *Store) fresh(t *vault.Tx, expected uint64) error {
	generation, err := s.generation(t)
	if err != nil {
		return err
	}
	if expected == 0 || expected != generation {
		return ErrStale
	}
	return nil
}

// change runs fn in one write transaction made against expected and counts
// it, so the list is then at expected + 1.
func (s *Store) change(expected uint64, fn func(t *vault.Tx) error) error {
	return s.v.Update(func(t *vault.Tx) error {
		if err := s.fresh(t, expected); err != nil {
			return err
		}
		if err := fn(t); err != nil {
			return err
		}
		return put(t, kindList, s.v.Index(kindList, "list"), listRecord{Generation: expected + 1})
	})
}

// Save adds one certificate, with the related certificates sent beside it and
// an optional key. The files are checked again here; a check the page ran
// earlier grants nothing. A key that does not match is kept only with ack.
func (s *Store) Save(expected uint64, files, key, keyPassword []byte, owner, location, fingerprint string, ack bool) (publicinventory.Record, uint64, error) {
	r, canonical, err := certificatepair.PrepareBundle(files, key, keyPassword, owner, location, fingerprint)
	defer clear(canonical)
	if err != nil || r.Fingerprint != fingerprint || (r.KeyStatus == "mismatch") != ack || len(canonical) > maxKeyBytes {
		return publicinventory.Record{}, 0, certificatepair.ErrInvalid
	}
	if !publicinventory.ValidOwner(owner) || (location != "" && publicinventory.ValidateLocation(location) != nil) {
		return publicinventory.Record{}, 0, publicinventory.ErrLabel
	}
	c := certificateRecord{
		Fingerprint: r.Fingerprint, Added: expected + 1, AddedAt: s.now().UTC().Format("2006-01-02T15:04:05Z"),
		DER: r.DER, Subject: r.Subject, Issuer: r.Issuer, DNSNames: r.DNSNames, NotBefore: r.NotBefore, NotAfter: r.NotAfter,
		Owner: owner, Bundle: r.BundleDER, Issuers: r.IssuerDER, HasKey: len(canonical) > 0, KeyStatus: r.KeyStatus,
	}
	if len(c.Bundle) == 0 {
		c.Bundle = [][]byte{r.DER}
	}
	if location != "" {
		c.Locations = []string{location}
	}
	err = s.change(expected, func(t *vault.Tx) error {
		ids, err := t.IDs(kindCertificate)
		if err != nil {
			return ErrUnavailable
		}
		id := s.v.Index(kindCertificate, c.Fingerprint)
		if slices.Contains(ids, id) {
			return publicinventory.ErrDuplicate
		}
		if len(ids) >= MaxCertificates {
			return ErrFull
		}
		if err := put(t, kindCertificate, id, c); err != nil {
			return err
		}
		if len(canonical) == 0 {
			return nil
		}
		return put(t, kindKey, id, keyRecord{Key: canonical, MismatchAcknowledged: ack})
	})
	if err != nil {
		return publicinventory.Record{}, 0, err
	}
	return c.record(), expected + 1, nil
}

// prepareKey checks a key against a saved certificate without saving it.
func prepareKey(c certificateRecord, key, keyPassword []byte) (publicinventory.Record, []byte, error) {
	if c.HasKey {
		return publicinventory.Record{}, nil, ErrKeyExists
	}
	if len(key) == 0 {
		return publicinventory.Record{}, nil, certificatepair.ErrInvalid
	}
	public := certificatepair.PublicPEM(c.Bundle)
	defer clear(public)
	r, canonical, err := certificatepair.PrepareBundle(public, key, keyPassword, "", "", c.Fingerprint)
	if err != nil || len(canonical) == 0 || len(canonical) > maxKeyBytes {
		clear(canonical)
		if err == nil {
			err = certificatepair.ErrInvalid
		}
		return publicinventory.Record{}, nil, err
	}
	out := c
	out.HasKey, out.KeyStatus, out.Bundle, out.Issuers = r.HasPrivateKey, r.KeyStatus, r.BundleDER, r.IssuerDER
	if len(out.Bundle) == 0 {
		out.Bundle = [][]byte{c.DER}
	}
	return out.record(), canonical, nil
}

// CheckKey says whether a key belongs to a saved certificate. Nothing is
// written.
func (s *Store) CheckKey(expected uint64, fingerprint string, key, keyPassword []byte) (publicinventory.Record, error) {
	var out publicinventory.Record
	err := s.v.View(func(t *vault.Tx) error {
		if err := s.fresh(t, expected); err != nil {
			return err
		}
		c, _, err := s.read(t, fingerprint)
		if err != nil {
			return err
		}
		r, canonical, err := prepareKey(c, key, keyPassword)
		clear(canonical)
		out = r
		return err
	})
	return out, err
}

// AttachKey saves a key with a certificate that has none. It never replaces
// a key. A key that does not match is kept only with ack.
func (s *Store) AttachKey(expected uint64, fingerprint string, key, keyPassword []byte, ack bool) (publicinventory.Record, uint64, error) {
	var out publicinventory.Record
	err := s.change(expected, func(t *vault.Tx) error {
		c, id, err := s.read(t, fingerprint)
		if err != nil {
			return err
		}
		r, canonical, err := prepareKey(c, key, keyPassword)
		defer clear(canonical)
		if err != nil {
			return err
		}
		if (r.KeyStatus == "mismatch") != ack {
			return certificatepair.ErrInvalid
		}
		c.HasKey, c.KeyStatus, c.Bundle, c.Issuers = r.HasPrivateKey, r.KeyStatus, r.BundleDER, r.IssuerDER
		if len(c.Bundle) == 0 {
			c.Bundle = [][]byte{c.DER}
		}
		if err := put(t, kindCertificate, id, c); err != nil {
			return err
		}
		if err := put(t, kindKey, id, keyRecord{Key: canonical, MismatchAcknowledged: ack}); err != nil {
			return err
		}
		out = c.record()
		return nil
	})
	if err != nil {
		return publicinventory.Record{}, 0, err
	}
	return out, expected + 1, nil
}

func (s *Store) edit(expected uint64, fingerprint string, change func(publicinventory.Record) (publicinventory.Record, error)) (publicinventory.Record, uint64, error) {
	var out publicinventory.Record
	err := s.change(expected, func(t *vault.Tx) error {
		c, id, err := s.read(t, fingerprint)
		if err != nil {
			return err
		}
		changed, err := change(c.record())
		if err != nil {
			return err
		}
		c.Owner, c.Locations = changed.Owner, slices.Clone(changed.Locations)
		if err := put(t, kindCertificate, id, c); err != nil {
			return err
		}
		out = c.record()
		return nil
	})
	if err != nil {
		return publicinventory.Record{}, 0, err
	}
	return out, expected + 1, nil
}

// AddLocation notes one more place the certificate is used.
func (s *Store) AddLocation(expected uint64, fingerprint, location string) (publicinventory.Record, uint64, error) {
	return s.edit(expected, fingerprint, func(r publicinventory.Record) (publicinventory.Record, error) {
		return publicinventory.AssociateLocation(r, location)
	})
}

// ChangeLocation renames or removes one place.
func (s *Store) ChangeLocation(expected uint64, fingerprint, old, renamed string, action LocationChange) (publicinventory.Record, uint64, error) {
	return s.edit(expected, fingerprint, func(r publicinventory.Record) (publicinventory.Record, error) {
		switch action {
		case Rename:
			return publicinventory.RenameLocation(r, old, renamed)
		case Remove:
			return publicinventory.RemoveLocation(r, old)
		}
		return publicinventory.Record{}, publicinventory.ErrLabel
	})
}

// SetOwner changes the owner note; an empty owner clears it.
func (s *Store) SetOwner(expected uint64, fingerprint, owner string) (publicinventory.Record, uint64, error) {
	return s.edit(expected, fingerprint, func(r publicinventory.Record) (publicinventory.Record, error) {
		return publicinventory.UpdateOwner(r, owner)
	})
}

// Delete removes a certificate and its key. A certificate with a key is
// removed only when keyAllowed: the person entered a fresh phone code.
func (s *Store) Delete(expected uint64, fingerprint string, keyAllowed bool) (uint64, error) {
	err := s.change(expected, func(t *vault.Tx) error {
		c, id, err := s.read(t, fingerprint)
		if err != nil {
			return err
		}
		if c.HasKey && !keyAllowed {
			return ErrKeyNeedsCode
		}
		if t.Delete(kindKey, id) != nil || t.Delete(kindCertificate, id) != nil {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return expected + 1, nil
}

// WithCertificate lends a certificate and its key, if any, for one use. The
// key is cleared afterwards, so use must not keep it. A key that does not
// match its certificate is lent too; callers that need a pair check
// KeyStatus is "matched". use runs after the read has ended, so slow work
// such as encrypting a download never holds the vault open.
func (s *Store) WithCertificate(expected uint64, fingerprint string, use func(publicinventory.Record, []byte) error) error {
	var c certificateRecord
	var k keyRecord
	defer func() { clear(k.Key) }()
	err := s.v.View(func(t *vault.Tx) error {
		if err := s.fresh(t, expected); err != nil {
			return err
		}
		var id string
		var err error
		if c, id, err = s.read(t, fingerprint); err != nil || !c.HasKey {
			return err
		}
		plain, _, err := t.Get(kindKey, id)
		defer clear(plain)
		if err != nil || strictJSON(plain, &k) != nil || len(k.Key) == 0 || len(k.Key) > maxKeyBytes ||
			k.MismatchAcknowledged != (c.KeyStatus == "mismatch") {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return err
	}
	return use(c.record(), k.Key)
}
