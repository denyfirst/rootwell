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
	maxRecords   = 500
	maxDERBytes  = 64 << 10
	maxLabel     = 128
	maxLocations = 32
)

var (
	ErrDuplicate         = errors.New("certificate is already in the inventory draft")
	ErrCapacity          = errors.New("inventory draft capacity reached")
	ErrLabel             = errors.New("inventory label is invalid")
	ErrCertSize          = errors.New("certificate exceeds inventory draft size limit")
	ErrLocationDuplicate = errors.New("location is already associated with this certificate")
	ErrLocationCapacity  = errors.New("certificate location capacity reached")
	ErrLocationMissing   = errors.New("location is no longer listed for this certificate")
	ErrLocationUnchanged = errors.New("certificate location is unchanged")
	ErrOwnerUnchanged    = errors.New("certificate owner is unchanged")
)

// Record contains public certificate bytes and unverified metadata. Owner and
// Location may be empty, meaning unknown; Location is the first of the
// operator-declared Locations. No field implies deployment, chain trust,
// hostname suitability, revocation status, or private-key possession.
type Record struct {
	Fingerprint string
	// ImportGeneration is set only by authenticated durable storage. Zero
	// means this record is an unsaved in-memory draft.
	ImportGeneration uint64
	// ImportedAt is the server-clock observation for a durable import. Empty
	// for an unsaved draft or an older image without that field.
	ImportedAt string
	DER        []byte
	Subject    string
	Issuer     string
	DNSNames   []string
	NotBefore  string
	NotAfter   string
	Owner      string
	Location   string
	// Locations are operator-declared, unverified uses of this certificate.
	// Location remains the first label for existing inventory consumers.
	Locations []string
	// HasPrivateKey is authenticated custody metadata, never key material.
	HasPrivateKey bool
	// KeyStatus is derived from authenticated material: not-added, matched or
	// mismatch. A mismatch is a loose attachment, never a usable pair.
	KeyStatus string
	BundleDER [][]byte
	IssuerDER [][]byte
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
		record := Record{
			Fingerprint: info.SHA256Fingerprint,
			DER:         bytes.Clone(entry.DER),
			Subject:     info.Subject,
			Issuer:      info.Issuer,
			DNSNames:    append([]string(nil), info.DNSNames...),
			NotBefore:   info.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
			NotAfter:    info.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
			Owner:       owner,
			Location:    location,
		}
		if location != "" {
			record.Locations = []string{location}
		}
		batch = append(batch, record)
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

// AssociateLocation returns a detached record with one more explicit,
// unverified location. Exact duplicate labels never create a second use.
func AssociateLocation(record Record, location string) (Record, error) {
	if err := ValidateLocation(location); err != nil {
		return Record{}, err
	}
	if !validLocationState(record) {
		return Record{}, ErrLabel
	}
	for _, existing := range record.Locations {
		if existing == location {
			return Record{}, ErrLocationDuplicate
		}
	}
	if len(record.Locations) >= maxLocations {
		return Record{}, ErrLocationCapacity
	}
	out := cloneRecords([]Record{record})[0]
	out.Locations = append(out.Locations, location)
	if out.Location == "" {
		out.Location = location
	}
	return out, nil
}

// RenameLocation corrects exactly one operator note; it does not alter DER or
// prove where the certificate is deployed.
func RenameLocation(record Record, oldLabel, newLabel string) (Record, error) {
	if ValidateLocation(oldLabel) != nil || ValidateLocation(newLabel) != nil || !validLocationState(record) {
		return Record{}, ErrLabel
	}
	if oldLabel == newLabel {
		return Record{}, ErrLocationUnchanged
	}
	index := -1
	for i, label := range record.Locations {
		if label == oldLabel {
			index = i
		} else if label == newLabel {
			return Record{}, ErrLocationDuplicate
		}
	}
	if index < 0 {
		return Record{}, ErrLocationMissing
	}
	out := cloneRecords([]Record{record})[0]
	out.Locations[index] = newLabel
	out.Location = out.Locations[0]
	return out, nil
}

// RemoveLocation deletes only the selected manual label. An empty list means
// unknown, not that the certificate was removed from any server.
func RemoveLocation(record Record, label string) (Record, error) {
	if ValidateLocation(label) != nil || !validLocationState(record) {
		return Record{}, ErrLabel
	}
	index := -1
	for i, existing := range record.Locations {
		if existing == label {
			index = i
			break
		}
	}
	if index < 0 {
		return Record{}, ErrLocationMissing
	}
	out := cloneRecords([]Record{record})[0]
	out.Locations = append(out.Locations[:index], out.Locations[index+1:]...)
	out.Location = ""
	if len(out.Locations) > 0 {
		out.Location = out.Locations[0]
	}
	return out, nil
}

func validLocationState(record Record) bool {
	return (len(record.Locations) == 0 && record.Location == "") ||
		(len(record.Locations) > 0 && record.Locations[0] == record.Location && len(record.Locations) <= maxLocations)
}

// ValidateLocation checks a manual location label without consulting any
// certificate or revealing whether a fingerprint exists in the inventory.
func ValidateLocation(location string) error {
	if location == "" || !validLabel(location) {
		return ErrLabel
	}
	return nil
}

// ValidOwner permits an empty label to represent an unknown owner.
func ValidOwner(owner string) bool {
	return validLabel(owner)
}

// UpdateOwner changes only an operator-declared label. An empty owner clears
// the note; it does not delete or otherwise change the certificate.
func UpdateOwner(record Record, owner string) (Record, error) {
	if !ValidOwner(owner) {
		return Record{}, ErrLabel
	}
	if owner == record.Owner {
		return Record{}, ErrOwnerUnchanged
	}
	out := cloneRecords([]Record{record})[0]
	out.Owner = owner
	return out, nil
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
		out[i].Locations = append([]string(nil), record.Locations...)
		out[i].BundleDER = cloneDER(record.BundleDER)
		out[i].IssuerDER = cloneDER(record.IssuerDER)
	}
	return out
}

func cloneDER(input [][]byte) [][]byte {
	out := make([][]byte, len(input))
	for i := range input {
		out[i] = bytes.Clone(input[i])
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
