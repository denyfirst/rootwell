// Package publicinventory models an in-memory draft of a public-certificate
// inventory. It does not persist records or authorize a trust verdict.
package publicinventory

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/publicbundle"
)

const (
	maxRecords  = 500
	maxDERBytes = 64 << 10
	maxLabel    = 128
)

var (
	ErrDuplicate = errors.New("certificate is already in the inventory draft")
	ErrCapacity  = errors.New("inventory draft capacity reached")
	ErrLabel     = errors.New("inventory label is invalid")
	ErrCertSize  = errors.New("certificate exceeds inventory draft size limit")
)

// Record contains public certificate bytes and unverified metadata. Owner and
// Location may be empty, meaning unknown. A later deployment model may attach
// multiple locations to one fingerprint. No field implies chain trust,
// hostname suitability, revocation status, or private-key possession.
type Record struct {
	Fingerprint string
	DER         []byte
	Subject     string
	Issuer      string
	DNSNames    []string
	NotBefore   string
	NotAfter    string
	Owner       string
	Location    string
}

// Catalog is an in-memory, single-process draft. Its contents disappear when
// the process exits; it is not an encrypted inventory or a backup.
type Catalog struct {
	mu      sync.RWMutex
	records []Record
	seen    map[string]struct{}
}

// Add parses one bounded public DER certificate or PEM bundle and atomically
// adds all its certificates. Any invalid, oversized, or duplicate member
// rejects the entire import; no partial inventory is left behind.
func (c *Catalog) Add(input []byte, owner, location string) ([]Record, error) {
	if !validLabel(owner) || !validLabel(location) {
		return nil, ErrLabel
	}
	entries, err := publicbundle.Parse(input)
	if err != nil {
		return nil, err
	}
	batch := make([]Record, 0, len(entries))
	for _, entry := range entries {
		if len(entry.DER) > maxDERBytes {
			return nil, ErrCertSize
		}
		info := entry.Inspection
		batch = append(batch, Record{
			Fingerprint: info.SHA256Fingerprint,
			DER:         bytes.Clone(entry.DER),
			Subject:     info.Subject,
			Issuer:      info.Issuer,
			DNSNames:    append([]string(nil), info.DNSNames...),
			NotBefore:   info.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
			NotAfter:    info.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
			Owner:       owner,
			Location:    location,
		})
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.records)+len(batch) > maxRecords {
		return nil, ErrCapacity
	}
	for _, record := range batch {
		if _, exists := c.seen[record.Fingerprint]; exists {
			return nil, ErrDuplicate
		}
	}
	if c.seen == nil {
		c.seen = make(map[string]struct{})
	}
	for _, record := range batch {
		c.seen[record.Fingerprint] = struct{}{}
		c.records = append(c.records, record)
	}
	return cloneRecords(batch), nil
}

// List returns detached copies so callers cannot mutate the catalog.
func (c *Catalog) List() []Record {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneRecords(c.records)
}

func cloneRecords(records []Record) []Record {
	out := make([]Record, len(records))
	for i, record := range records {
		out[i] = record
		out[i].DER = bytes.Clone(record.DER)
		out[i].DNSNames = append([]string(nil), record.DNSNames...)
	}
	return out
}

func validLabel(value string) bool {
	if len(value) > maxLabel || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return false
		}
	}
	return true
}
