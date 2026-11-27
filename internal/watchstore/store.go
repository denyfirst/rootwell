// Package watchstore keeps the websites Rootwell checks every six hours, and what
// each served when it was last checked (ADR 0093). Each site is one sealed
// vault record, indexed by an HMAC of its target, so the file does not list
// the names. It reaches no network: the daemon checks, and this package
// remembers.
package watchstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/vault"
)

const (
	kind = "watched-site"
	// MaxSites is how many websites may be watched.
	MaxSites = 50
	// Every is how often a site is checked.
	Every = 6 * time.Hour
)

var (
	// ErrFull says MaxSites are watched already.
	ErrFull = errors.New("50 websites are watched already")
	// ErrWatched says the site is watched already.
	ErrWatched = errors.New("this website is watched already")
	// ErrNotWatched says the site is not watched.
	ErrNotWatched = errors.New("this website is not watched")
	// ErrUnavailable hides a vault refusal: a damaged or unreadable record.
	ErrUnavailable = errors.New("the watched websites could not be read")
)

// Site is one watched website and what its last check found.
type Site struct {
	// Target is the website as Website check writes it: a name or address,
	// with its port when that is not 443.
	Target  string `json:"target"`
	AddedAt string `json:"added_at"`
	// CheckedAt is when it was last checked; "" before the first check.
	CheckedAt string `json:"checked_at,omitempty"`
	// State is the last verdict: "verified", "attention", "failed" (the
	// chain or the name is wrong) or "unreachable"; "" before the first check.
	State string `json:"state,omitempty"`
	// Problem says, in one sentence, what is wrong; "" when nothing is.
	Problem string `json:"problem,omitempty"`
	// Leaf is the fingerprint of the certificate the site served, its name
	// and its end; Since is when the site began to serve it.
	Leaf     string `json:"leaf,omitempty"`
	LeafName string `json:"leaf_name,omitempty"`
	NotAfter string `json:"not_after,omitempty"`
	Since    string `json:"since,omitempty"`
	// Told is what the last alert was about, so one change is told once.
	Told string `json:"told,omitempty"`
}

// Result is what one check found. A site that could not be reached has an
// empty Leaf.
type Result struct {
	State    string
	Problem  string
	Leaf     string
	LeafName string
	NotAfter string
}

// Change is what a check changed that a person should hear about.
type Change struct {
	Site Site
	// NewCertificate says the site now serves another certificate;
	// Previous names the end of the one it served before.
	NewCertificate bool
	PreviousEnd    string
	// NewProblem says the site has a problem it did not have.
	NewProblem bool
}

// Store reads and changes the watched sites. It is safe for concurrent use.
type Store struct {
	v   *vault.Store
	now func() time.Time
}

// New uses an open vault.
func New(v *vault.Store) *Store { return &Store{v: v, now: time.Now} }

func strict(data []byte, v any) error {
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

func (s *Store) read(t *vault.Tx, id string) (Site, error) {
	plain, _, err := t.Get(kind, id)
	defer clear(plain)
	if err != nil {
		if errors.Is(err, vault.ErrMissing) {
			return Site{}, ErrNotWatched
		}
		return Site{}, ErrUnavailable
	}
	var site Site
	if strict(plain, &site) != nil || site.Target == "" || s.v.Index(kind, site.Target) != id || site.AddedAt == "" {
		return Site{}, ErrUnavailable
	}
	return site, nil
}

func (s *Store) put(t *vault.Tx, site Site) error {
	plain, err := json.Marshal(site)
	defer clear(plain)
	if err != nil || t.Put(kind, s.v.Index(kind, site.Target), plain) != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) all(t *vault.Tx) ([]Site, error) {
	ids, err := t.IDs(kind)
	if err != nil {
		return nil, ErrUnavailable
	}
	sites := make([]Site, 0, len(ids))
	for _, id := range ids {
		site, err := s.read(t, id)
		if err != nil {
			return nil, err
		}
		sites = append(sites, site)
	}
	slices.SortFunc(sites, func(a, b Site) int { return strings.Compare(a.Target, b.Target) })
	return sites, nil
}

// List returns the watched sites, by target.
func (s *Store) List() ([]Site, error) {
	var sites []Site
	err := s.v.View(func(t *vault.Tx) error {
		var err error
		sites, err = s.all(t)
		return err
	})
	return sites, err
}

// Add watches a site. The target must already be in Website check's
// canonical form; the caller parses it.
func (s *Store) Add(target string) (Site, error) {
	site := Site{Target: target, AddedAt: s.now().UTC().Format(time.RFC3339)}
	err := s.v.Update(func(t *vault.Tx) error {
		sites, err := s.all(t)
		if err != nil {
			return err
		}
		if slices.ContainsFunc(sites, func(other Site) bool { return other.Target == target }) {
			return ErrWatched
		}
		if len(sites) >= MaxSites {
			return ErrFull
		}
		return s.put(t, site)
	})
	if err != nil {
		return Site{}, err
	}
	return site, nil
}

// Remove stops watching a site.
func (s *Store) Remove(target string) error {
	return s.v.Update(func(t *vault.Tx) error {
		id := s.v.Index(kind, target)
		if _, err := s.read(t, id); err != nil {
			return err
		}
		if t.Delete(kind, id) != nil {
			return ErrUnavailable
		}
		return nil
	})
}

// Due lists the sites not checked in the last six hours, the longest waiting
// first.
func (s *Store) Due(now time.Time) ([]Site, error) {
	sites, err := s.List()
	if err != nil {
		return nil, err
	}
	var due []Site
	for _, site := range sites {
		checked, err := time.Parse(time.RFC3339, site.CheckedAt)
		if site.CheckedAt == "" || err != nil || now.Sub(checked) >= Every {
			due = append(due, site)
		}
	}
	slices.SortFunc(due, func(a, b Site) int { return strings.Compare(a.CheckedAt, b.CheckedAt) })
	return due, nil
}

// Record keeps what one check found and says what changed: another
// certificate, or a problem the site did not have. Each change is told once:
// a site that stays broken, or keeps serving the new certificate, says
// nothing more. A site removed meanwhile is left removed.
func (s *Store) Record(target string, r Result, now time.Time) (*Change, error) {
	var change *Change
	err := s.v.Update(func(t *vault.Tx) error {
		site, err := s.read(t, s.v.Index(kind, target))
		if errors.Is(err, ErrNotWatched) {
			return nil
		}
		if err != nil {
			return err
		}
		first := site.CheckedAt == ""
		at := now.UTC().Format(time.RFC3339)
		next := site
		next.CheckedAt, next.State, next.Problem = at, r.State, r.Problem
		c := Change{}
		if r.Leaf != "" {
			if r.Leaf != site.Leaf {
				next.Since = at
				c.NewCertificate = !first && site.Leaf != ""
				c.PreviousEnd = site.NotAfter
			}
			next.Leaf, next.LeafName, next.NotAfter = r.Leaf, r.LeafName, r.NotAfter
		}
		key := next.Leaf + "|" + next.State
		if first {
			// The person saw this result when they chose to watch the site.
			next.Told = key
			return s.put(t, next)
		}
		if r.State != "verified" && key != site.Told {
			c.NewProblem = true
		}
		if c.NewCertificate || c.NewProblem {
			next.Told = key
			c.Site = next
			change = &c
		} else if r.State == "verified" {
			next.Told = key
		}
		return s.put(t, next)
	})
	if err != nil {
		return nil, err
	}
	return change, nil
}
