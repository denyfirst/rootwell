// Package servingstore keeps the certificate Rootwell serves its own pages
// with in the vault (ADR 0088): the local certificate authority, the names it
// may sign for, and the current server certificate. They are one sealed
// record, so the authority's key never leaves the vault.
//
// The first start makes an authority for this host's loopback names. The
// operator adds LAN or VPN names with `rootwelld serving-names`, which makes a
// new authority, since an authority's names are fixed when it is made. The
// server certificate lasts 90 days and is replaced 30 days before it ends.
package servingstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/denyfirst/rootwell/internal/servecert"
	"github.com/denyfirst/rootwell/internal/vault"
)

const kind = "serving"

var (
	// ErrRefused says a name was not accepted.
	ErrRefused = errors.New("serving name refused")
	// ErrUnavailable hides a vault refusal or a damaged record.
	ErrUnavailable = errors.New("the serving certificate could not be read")
)

type record struct {
	// Names are the names the operator added; the loopback names are always
	// there besides.
	Names        []string `json:"names"`
	Authority    []byte   `json:"authority"`
	AuthorityKey []byte   `json:"authority_key"`
	Certificate  []byte   `json:"certificate"`
	Key          []byte   `json:"key"`
}

// Serving is what the server needs: the names it answers to, the authority a
// browser trusts, and the certificate it presents.
type Serving struct {
	Added       []string
	Names       servecert.Names
	Authority   *x509.Certificate
	Certificate *tls.Certificate
}

// Fingerprint is the authority's SHA-256 fingerprint, as a browser shows it.
func (s Serving) Fingerprint() string { return servecert.Fingerprint(s.Authority) }

func id(v *vault.Store) string { return v.Index(kind, "serving") }

func read(t *vault.Tx, v *vault.Store) (record, bool, error) {
	plain, _, err := t.Get(kind, id(v))
	defer clear(plain)
	if errors.Is(err, vault.ErrMissing) {
		return record{}, false, nil
	}
	var r record
	if err != nil {
		return record{}, false, ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.More() {
		return record{}, false, ErrUnavailable
	}
	return r, true, nil
}

func write(t *vault.Tx, v *vault.Store, r record) error {
	data, err := json.Marshal(r)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(data)
	if t.Put(kind, id(v), data) != nil {
		return ErrUnavailable
	}
	return nil
}

// open turns a stored record into what the server uses, and checks that the
// pieces belong together.
func open(r record) (Serving, error) {
	names, err := servecert.ParseNames(r.Names)
	if err != nil {
		return Serving{}, ErrUnavailable
	}
	authority, err := x509.ParseCertificate(r.Authority)
	if err != nil || !authority.IsCA {
		return Serving{}, ErrUnavailable
	}
	leaf, err := x509.ParseCertificate(r.Certificate)
	if err != nil || leaf.CheckSignatureFrom(authority) != nil {
		return Serving{}, ErrUnavailable
	}
	key, err := x509.ParsePKCS8PrivateKey(r.Key)
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if err != nil || !ok || !ecKey.PublicKey.Equal(leaf.PublicKey) {
		return Serving{}, ErrUnavailable
	}
	return Serving{Added: slices.Clone(r.Names), Names: names, Authority: authority,
		Certificate: &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: ecKey, Leaf: leaf}}, nil
}

// fresh makes a new authority for added names and a server certificate.
func fresh(added []string, now time.Time) (record, error) {
	names, err := servecert.ParseNames(added)
	if err != nil {
		return record{}, ErrRefused
	}
	authority, err := servecert.NewAuthority(names, now)
	if err != nil {
		return record{}, ErrUnavailable
	}
	r := record{Names: canonical(names), Authority: authority.Certificate.Raw}
	if r.AuthorityKey, err = x509.MarshalPKCS8PrivateKey(authority.Key); err != nil {
		return record{}, ErrUnavailable
	}
	return issue(r, authority, names, now)
}

// canonical lists the added names as ParseNames keeps them, without the
// loopback names it adds itself.
func canonical(names servecert.Names) []string {
	var out []string
	for _, name := range names.DNS {
		if name != "localhost" {
			out = append(out, name)
		}
	}
	for _, ip := range names.IPs {
		if !ip.IsLoopback() {
			out = append(out, ip.String())
		}
	}
	return out
}

func issue(r record, authority servecert.Authority, names servecert.Names, now time.Time) (record, error) {
	leaf, key, err := authority.Issue(names, now)
	if err != nil {
		return record{}, ErrUnavailable
	}
	r.Certificate = leaf.Raw
	if r.Key, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
		return record{}, ErrUnavailable
	}
	return r, nil
}

// current reads the record in a read-only transaction.
func current(v *vault.Store) (record, bool, error) {
	var r record
	var ok bool
	err := v.View(func(t *vault.Tx) error {
		var err error
		r, ok, err = read(t, v)
		return err
	})
	return r, ok, err
}

// renewed replaces the server certificate when servecert says it is due.
func renewed(r record, now time.Time) (record, bool, error) {
	present, err := open(r)
	if err != nil {
		return record{}, false, err
	}
	if !servecert.NeedsRenewal(present.Certificate.Leaf, present.Names, now) {
		return r, false, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(r.AuthorityKey)
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if err != nil || !ok || !ecKey.PublicKey.Equal(present.Authority.PublicKey) {
		return record{}, false, ErrUnavailable
	}
	next, err := issue(r, servecert.Authority{Certificate: present.Authority, Key: ecKey}, present.Names, now)
	return next, err == nil, err
}

// Ensure reads the serving certificate, making one for the loopback names the
// first time and replacing the server certificate when it is due. It reports
// whether it made a new authority. It writes only when something changed.
func Ensure(v *vault.Store, now time.Time) (Serving, bool, error) {
	r, ok, err := current(v)
	if err != nil {
		return Serving{}, false, err
	}
	if ok {
		out, _, err := Renew(v, now)
		return out, false, err
	}
	var out Serving
	err = v.Update(func(t *vault.Tx) error {
		if _, again, err := read(t, v); err != nil || again {
			// Another start made one in the meantime; read it next time.
			return errors.Join(err, ErrUnavailable)
		}
		if r, err = fresh(nil, now); err != nil {
			return err
		}
		if out, err = open(r); err != nil {
			return err
		}
		return write(t, v, r)
	})
	return out, err == nil, err
}

// Renew replaces the server certificate if it is due, and reports whether it
// did. A running server calls it from time to time; when nothing is due it
// only reads.
func Renew(v *vault.Store, now time.Time) (Serving, bool, error) {
	r, ok, err := current(v)
	if err != nil {
		return Serving{}, false, err
	}
	if !ok {
		return Serving{}, false, ErrUnavailable
	}
	if _, due, err := renewed(r, now); err != nil || !due {
		out, openErr := open(r)
		return out, false, errors.Join(err, openErr)
	}
	var out Serving
	err = v.Update(func(t *vault.Tx) error {
		r, ok, err := read(t, v)
		if err != nil || !ok {
			return errors.Join(err, ErrUnavailable)
		}
		if r, _, err = renewed(r, now); err != nil {
			return err
		}
		if out, err = open(r); err != nil {
			return err
		}
		return write(t, v, r)
	})
	return out, err == nil, err
}

// SetNames makes a new authority for these added names, with the loopback
// names always among them. Browsers must trust the new authority again.
func SetNames(v *vault.Store, added []string, now time.Time) (Serving, error) {
	r, err := fresh(added, now)
	if err != nil {
		return Serving{}, err
	}
	out, err := open(r)
	if err != nil {
		return Serving{}, err
	}
	err = v.Update(func(t *vault.Tx) error { return write(t, v, r) })
	return out, err
}
