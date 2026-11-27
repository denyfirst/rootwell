package certstore

// Requests and renewals.
//
// A certificate request (CSR) made by Rootwell keeps its new key in the vault:
// the person sends only the request to a certificate provider, and the key
// never travels. When the provider's certificate is added, Save finds the
// request by the certificate's public key, saves the request's key with it and
// closes the request, in one write.
//
// A request may renew a saved certificate. The new certificate then takes the
// older one's place: it keeps where the older one is used and who looks after
// it, and the older one is marked replaced. This is the person's bookkeeping
// only. Rootwell does not know what a server serves.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/publicinventory"
	"github.com/denyfirst/rootwell/internal/vault"
)

const (
	kindRequest    = "certificate-request"
	kindRequestKey = "certificate-request-key"
	// MaxRequests is how many requests may wait for their certificate.
	MaxRequests = 50
	maxCSRBytes = 16 << 10
)

var (
	// ErrRequestsFull says MaxRequests are waiting already.
	ErrRequestsFull = errors.New("too many requests are waiting for their certificate")
	// ErrRenewalWaiting says a request to renew this certificate is waiting
	// already.
	ErrRenewalWaiting = errors.New("a renewal of this certificate is waiting already")
	// ErrReplaced says the certificate was replaced by a newer one.
	ErrReplaced = errors.New("the certificate was replaced by a newer one")
	// ErrCannotReplace says a certificate cannot take another's place: the
	// older one is replaced already, outlasts it, is an authority, or has a
	// name the newer one does not.
	ErrCannotReplace = errors.New("this certificate cannot take that one's place")
	// ErrRequestNotFound says no such request is waiting.
	ErrRequestNotFound = errors.New("the request is not waiting")
)

// Request is a certificate request waiting for its certificate. Its key is a
// record of its own and never leaves through a Request.
type Request struct {
	// PublicFingerprint is the SHA-256 of the key's public part, which the
	// provider's certificate carries too.
	PublicFingerprint string
	CreatedAt         string
	// CSR is the request in PEM, as the provider wants it.
	CSR         []byte
	Subject     string
	DNSNames    []string
	IPAddresses []string
	KeyType     string
	// Renews names the saved certificate the request renews, if any.
	Renews string
}

type requestRecord struct {
	PublicFingerprint string   `json:"public_fingerprint"`
	CreatedAt         string   `json:"created_at"`
	CSR               []byte   `json:"csr"`
	Subject           string   `json:"subject"`
	DNSNames          []string `json:"dns_names,omitempty"`
	IPAddresses       []string `json:"ip_addresses,omitempty"`
	KeyType           string   `json:"key_type"`
	Renews            string   `json:"renews,omitempty"`
}

type requestKeyRecord struct {
	Key []byte `json:"key"`
}

func (q requestRecord) request() Request {
	return Request{PublicFingerprint: q.PublicFingerprint, CreatedAt: q.CreatedAt, CSR: bytes.Clone(q.CSR),
		Subject: q.Subject, DNSNames: slices.Clone(q.DNSNames), IPAddresses: slices.Clone(q.IPAddresses),
		KeyType: q.KeyType, Renews: q.Renews}
}

// PublicFingerprint is the SHA-256 of a public key's canonical form, in the
// colon-separated capitals the pages show.
func PublicFingerprint(public any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", ErrUnavailable
	}
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i := range sum {
		parts[i] = strings.ToUpper(hex.EncodeToString(sum[i : i+1]))
	}
	return strings.Join(parts, ":"), nil
}

// KeyType names a public key the way the pages do: "ECDSA P-256", "RSA 2048"
// or "Ed25519". Anything else is "".
func KeyType(public any) string {
	switch key := public.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", key.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + key.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return ""
}

// parseRequest reads one PEM request strictly and checks its signature.
func parseRequest(csr []byte) (*x509.CertificateRequest, error) {
	if len(csr) == 0 || len(csr) > maxCSRBytes {
		return nil, ErrUnavailable
	}
	block, rest := pem.Decode(csr)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrUnavailable
	}
	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || parsed.CheckSignature() != nil {
		return nil, ErrUnavailable
	}
	return parsed, nil
}

// readRequest opens one request and checks it sits under its own key's index.
func (s *Store) readRequest(t *vault.Tx, id string) (requestRecord, error) {
	plain, _, err := t.Get(kindRequest, id)
	defer clear(plain)
	if err != nil {
		if errors.Is(err, vault.ErrMissing) {
			return requestRecord{}, ErrRequestNotFound
		}
		return requestRecord{}, ErrUnavailable
	}
	var q requestRecord
	if strictJSON(plain, &q) != nil || !publicinventory.ValidFingerprint(q.PublicFingerprint) ||
		s.v.Index(kindRequest, q.PublicFingerprint) != id || q.CreatedAt == "" ||
		(q.Renews != "" && !publicinventory.ValidFingerprint(q.Renews)) {
		return requestRecord{}, ErrUnavailable
	}
	if _, err := parseRequest(q.CSR); err != nil {
		return requestRecord{}, ErrUnavailable
	}
	return q, nil
}

func (s *Store) requests(t *vault.Tx) ([]requestRecord, error) {
	ids, err := t.IDs(kindRequest)
	if err != nil {
		return nil, ErrUnavailable
	}
	out := make([]requestRecord, 0, len(ids))
	for _, id := range ids {
		q, err := s.readRequest(t, id)
		if err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	slices.SortFunc(out, func(a, b requestRecord) int {
		if c := strings.Compare(a.CreatedAt, b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.PublicFingerprint, b.PublicFingerprint)
	})
	return out, nil
}

// requestKey opens the key of one request. The caller clears it.
func (s *Store) requestKey(t *vault.Tx, id string) ([]byte, error) {
	plain, _, err := t.Get(kindRequestKey, id)
	defer clear(plain)
	var k requestKeyRecord
	if err != nil || strictJSON(plain, &k) != nil || len(k.Key) == 0 || len(k.Key) > maxKeyBytes {
		clear(k.Key)
		return nil, ErrUnavailable
	}
	return k.Key, nil
}

// ListAll returns the certificates, as List does, and the requests waiting
// for theirs, oldest first, read at one generation. No key is opened.
func (s *Store) ListAll() ([]publicinventory.Record, []Request, uint64, error) {
	var records []publicinventory.Record
	var waiting []Request
	var generation uint64
	err := s.v.View(func(t *vault.Tx) error {
		var err error
		if records, generation, err = s.list(t); err != nil {
			return err
		}
		stored, err := s.requests(t)
		if err != nil {
			return err
		}
		waiting = make([]Request, 0, len(stored))
		for _, q := range stored {
			waiting = append(waiting, q.request())
		}
		return nil
	})
	if err != nil {
		return nil, nil, 0, err
	}
	return records, waiting, generation, nil
}

// AddRequest keeps a request and its new key, made by
// csrworkbench.GenerateKept, until the certificate for it is added. The key
// must be the request's own. renews, when set, names a saved certificate
// that is not replaced and has no other renewal waiting.
func (s *Store) AddRequest(expected uint64, csr, key []byte, renews string) (Request, uint64, error) {
	parsed, err := parseRequest(csr)
	if err != nil || len(key) == 0 || len(key) > maxKeyBytes || (renews != "" && !publicinventory.ValidFingerprint(renews)) {
		return Request{}, 0, ErrUnavailable
	}
	private, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return Request{}, 0, ErrUnavailable
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		return Request{}, 0, ErrUnavailable
	}
	own, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || subtle.ConstantTimeCompare(own, parsed.RawSubjectPublicKeyInfo) != 1 {
		return Request{}, 0, ErrUnavailable
	}
	fingerprint, err := PublicFingerprint(parsed.PublicKey)
	if err != nil {
		return Request{}, 0, err
	}
	q := requestRecord{PublicFingerprint: fingerprint, CreatedAt: s.now().UTC().Format("2006-01-02T15:04:05Z"),
		CSR: bytes.Clone(csr), Subject: parsed.Subject.String(), DNSNames: slices.Clone(parsed.DNSNames),
		KeyType: KeyType(parsed.PublicKey), Renews: renews}
	for _, ip := range parsed.IPAddresses {
		q.IPAddresses = append(q.IPAddresses, ip.String())
	}
	err = s.change(expected, func(t *vault.Tx) error {
		waiting, err := s.requests(t)
		if err != nil {
			return err
		}
		if len(waiting) >= MaxRequests {
			return ErrRequestsFull
		}
		id := s.v.Index(kindRequest, q.PublicFingerprint)
		for _, other := range waiting {
			if other.PublicFingerprint == q.PublicFingerprint {
				return ErrUnavailable
			}
			if renews != "" && other.Renews == renews {
				return ErrRenewalWaiting
			}
		}
		if renews != "" {
			c, _, err := s.read(t, renews)
			if err != nil {
				return err
			}
			if c.ReplacedBy != "" {
				return ErrReplaced
			}
		}
		if err := put(t, kindRequest, id, q); err != nil {
			return err
		}
		return put(t, kindRequestKey, id, requestKeyRecord{Key: key})
	})
	if err != nil {
		return Request{}, 0, err
	}
	return q.request(), expected + 1, nil
}

// DeleteRequest gives up a request and deletes its key. The key never had a
// certificate, but it is a key: the caller asks for a fresh code first.
func (s *Store) DeleteRequest(expected uint64, publicFingerprint string) (uint64, error) {
	if !publicinventory.ValidFingerprint(publicFingerprint) {
		return 0, ErrRequestNotFound
	}
	err := s.change(expected, func(t *vault.Tx) error {
		id := s.v.Index(kindRequest, publicFingerprint)
		if _, err := s.readRequest(t, id); err != nil {
			return err
		}
		if t.Delete(kindRequestKey, id) != nil || t.Delete(kindRequest, id) != nil {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return expected + 1, nil
}

// waitingFor finds the request whose key is this certificate's. found is
// false when there is none.
func (s *Store) waitingFor(t *vault.Tx, der []byte) (requestRecord, string, bool, error) {
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return requestRecord{}, "", false, ErrUnavailable
	}
	fingerprint, err := PublicFingerprint(certificate.PublicKey)
	if err != nil {
		return requestRecord{}, "", false, err
	}
	id := s.v.Index(kindRequest, fingerprint)
	q, err := s.readRequest(t, id)
	if errors.Is(err, ErrRequestNotFound) {
		return requestRecord{}, "", false, nil
	}
	if err != nil {
		return requestRecord{}, "", false, err
	}
	return q, id, true, nil
}

// names lists what a certificate works for: its DNS names and IP addresses.
// An authority, or a certificate that cannot be read, works for nothing here.
func names(der []byte) []string {
	c, err := x509.ParseCertificate(der)
	if err != nil || c.IsCA {
		return nil
	}
	out := make([]string, 0, len(c.DNSNames)+len(c.IPAddresses))
	for _, name := range c.DNSNames {
		out = append(out, "dns:"+strings.ToLower(name))
	}
	for _, ip := range c.IPAddresses {
		out = append(out, "ip:"+ip.String())
	}
	return out
}

func ends(c certificateRecord) (time.Time, bool) {
	end, err := time.Parse(time.RFC3339, c.NotAfter)
	return end, err == nil
}

// outlasts says whether newer ends after older.
func outlasts(newer, older certificateRecord) bool {
	a, ok := ends(newer)
	b, ok2 := ends(older)
	return ok && ok2 && a.After(b)
}

// mayTakeOver says whether newer may take older's place when the person
// picks it: older is another certificate, not replaced, not an authority,
// with names newer covers every one of, and newer ends later.
func mayTakeOver(newer, older certificateRecord) bool {
	if older.Fingerprint == newer.Fingerprint || older.ReplacedBy != "" || !outlasts(newer, older) {
		return false
	}
	old := names(older.DER)
	if len(old) == 0 {
		return false
	}
	covered := names(newer.DER)
	for _, name := range old {
		if !slices.Contains(covered, name) {
			return false
		}
	}
	return true
}

// renews says whether a finished renewal still takes older's place: the
// person chose older when making the request, so neither names nor end dates
// are asked about. An early renewal may end before the older one, now that
// certificates last shorter; it is still the one the person asked for.
func renews(newer, older certificateRecord) bool {
	return older.Fingerprint != newer.Fingerprint && older.ReplacedBy == ""
}

// takeOver gives c the place of the saved certificate older: c keeps where
// older is used and, when c has none, who looks after it, and older is
// marked replaced. renewal is for a finished renewal request (see renews):
// an older one deleted or replaced since then is passed over.
//
// It returns the fingerprint of the certificate replaced, or "".
func (s *Store) takeOver(t *vault.Tx, c *certificateRecord, older string, renewal bool) (string, error) {
	old, id, err := s.read(t, older)
	if err != nil {
		if renewal && errors.Is(err, ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	allowed := mayTakeOver(*c, old)
	if renewal {
		allowed = renews(*c, old)
		if !allowed {
			return "", nil
		}
	}
	if !allowed {
		return "", ErrCannotReplace
	}
	now := s.now().UTC().Format("2006-01-02T15:04:05Z")
	places := slices.Clone(old.Locations)
	for _, place := range c.Locations {
		if !slices.Contains(places, place) && len(places) < publicinventory.MaxLocations {
			places = append(places, place)
		}
	}
	c.Locations = places
	if c.Owner == "" {
		c.Owner = old.Owner
	}
	old.ReplacedBy, old.ReplacedAt = c.Fingerprint, now
	if err := put(t, kindCertificate, id, old); err != nil {
		return "", err
	}
	return old.Fingerprint, nil
}

// Plan is what saving a certificate would do.
type Plan struct {
	// Finishes says its key is the key of a request kept here.
	Finishes bool
	// Renews names the saved certificate that request renews, whose place
	// saving takes.
	Renews string
	// Replaces names, when nothing is renewed, the latest ending saved
	// certificate it may take over by name, if the person agrees.
	Replaces string
}

// Successor says, without writing, what saving this certificate would do.
func (s *Store) Successor(r publicinventory.Record) (Plan, error) {
	var plan Plan
	newer := certificateRecord{Fingerprint: r.Fingerprint, DER: r.DER, NotAfter: r.NotAfter}
	err := s.v.View(func(t *vault.Tx) error {
		q, _, found, err := s.waitingFor(t, r.DER)
		if err != nil {
			return err
		}
		plan.Finishes = found
		if found && q.Renews != "" {
			old, _, err := s.read(t, q.Renews)
			if err == nil && renews(newer, old) {
				plan.Renews = old.Fingerprint
				return nil
			}
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		ids, err := t.IDs(kindCertificate)
		if err != nil {
			return ErrUnavailable
		}
		var best certificateRecord
		for _, id := range ids {
			old, err := s.readID(t, id)
			if err != nil {
				return err
			}
			if mayTakeOver(newer, old) && (best.Fingerprint == "" || outlasts(old, best)) {
				best = old
			}
		}
		plan.Replaces = best.Fingerprint
		return nil
	})
	if err != nil {
		return Plan{}, err
	}
	return plan, nil
}
