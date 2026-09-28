// Package inventorystore authenticates a bounded, complete inventory image.
// Filesystem transactions and backup policy belong to a separate layer.
package inventorystore

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math"
	"time"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

const (
	// DER is base64-encoded inside each encrypted record and the manifest is
	// base64-encoded again by its authenticated outer envelope.
	maxImage      = 96 << 20
	maxRecords    = 500
	maxGeneration = 1_000_000 // far below the random-nonce GCM per-key limit
	macLabel      = "rootwell.public-inventory.manifest.v1:"
)

var (
	ErrInvalid         = errors.New("inventory image is invalid")
	ErrLimit           = errors.New("inventory image limit reached")
	ErrNotFound        = errors.New("certificate is not in the inventory")
	ErrStaleGeneration = errors.New("inventory changed since it was displayed")
)

type sealedRecord struct {
	ID         []byte `json:"id"`
	Generation uint64 `json:"generation"`
	Ciphertext []byte `json:"ciphertext"`
}

type manifest struct {
	Version        int            `json:"version"`
	InstallationID []byte         `json:"installation_id"`
	Generation     uint64         `json:"generation"`
	Records        []sealedRecord `json:"records"`
}

type envelope struct {
	Body []byte `json:"body"`
	MAC  []byte `json:"mac"`
}

type payload struct {
	DER                 []byte   `json:"der"`
	Owner               string   `json:"owner"`
	Location            string   `json:"location"`
	AdditionalLocations []string `json:"additional_locations,omitempty"`
	ImportedAt          string   `json:"imported_at,omitempty"`
	ImportGeneration    uint64   `json:"import_generation,omitempty"`
}

type LocationChange uint8

const (
	LocationRename LocationChange = 1 + iota
	LocationRemove
)

// Create returns an authenticated empty image. Generation 1 is reserved for
// creation; every later successful import advances it exactly once.
func Create(key, installationID []byte) ([]byte, error) {
	if !validIdentity(key, installationID) {
		return nil, ErrInvalid
	}
	return encode(key, manifest{Version: 1, InstallationID: bytes.Clone(installationID), Generation: 1, Records: []sealedRecord{}})
}

// Open authenticates the whole manifest and every encrypted record before
// returning detached public certificate records. It cannot detect replay of
// an older *complete* image without an external trusted generation anchor.
func Open(key, installationID, image []byte) ([]publicinventory.Record, uint64, error) {
	m, records, err := decode(key, installationID, image)
	if err != nil {
		return nil, 0, err
	}
	return records, m.Generation, nil
}

// Append validates a complete existing image and an all-or-nothing public
// import, then returns a replacement image. The caller must atomically commit
// it under one writer lock; this function never writes to disk.
func Append(key, installationID, image, input []byte, owner, location string) ([]byte, []publicinventory.Record, error) {
	m, existing, err := decode(key, installationID, image)
	if err != nil {
		return nil, nil, err
	}
	if m.Generation >= maxGeneration {
		return nil, nil, ErrLimit
	}
	var catalog publicinventory.Catalog
	for _, r := range existing {
		if _, err := catalog.Add(r.DER, r.Owner, r.Location); err != nil {
			return nil, nil, ErrInvalid
		}
	}
	added, err := catalog.Add(input, owner, location)
	if err != nil {
		return nil, nil, err
	}
	if len(m.Records)+len(added) > maxRecords {
		return nil, nil, ErrLimit
	}
	m.Generation++
	importedAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	for i, r := range added {
		id := sha256.Sum256(r.DER)
		plain, err := json.Marshal(payload{DER: r.DER, Owner: r.Owner, Location: r.Location, ImportedAt: importedAt})
		if err != nil {
			return nil, nil, ErrInvalid
		}
		var install [16]byte
		copy(install[:], installationID)
		ciphertext, err := inventoryseal.Seal(key, inventoryseal.Context{InstallationID: install, RecordID: id, Generation: m.Generation}, plain)
		if err != nil {
			return nil, nil, err
		}
		m.Records = append(m.Records, sealedRecord{ID: id[:], Generation: m.Generation, Ciphertext: ciphertext})
		added[i].ImportGeneration = m.Generation
		added[i].ImportedAt = importedAt
	}
	result, err := encode(key, m)
	if err != nil {
		return nil, nil, err
	}
	return result, added, nil
}

// AssociateLocation updates one existing certificate without duplicating its
// DER or changing its original import provenance. The caller supplies the
// generation last displayed to the operator and atomically installs the
// returned complete image under the writer lock.
func AssociateLocation(key, installationID, image []byte, fingerprint, location string, expectedGeneration uint64) ([]byte, publicinventory.Record, uint64, error) {
	m, existing, err := decode(key, installationID, image)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	if expectedGeneration == 0 || m.Generation != expectedGeneration {
		return nil, publicinventory.Record{}, 0, ErrStaleGeneration
	}
	if m.Generation >= maxGeneration {
		return nil, publicinventory.Record{}, 0, ErrLimit
	}
	if err := publicinventory.ValidateLocation(location); err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	index := -1
	for i, record := range existing {
		if record.Fingerprint == fingerprint {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, publicinventory.Record{}, 0, ErrNotFound
	}
	updated, err := publicinventory.AssociateLocation(existing[index], location)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	result, generation, err := resealRecord(key, installationID, m, index, updated)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	return result, updated, generation, err
}

// UpdateOwner replaces one unverified owner note. Clearing it is explicit;
// the certificate, its locations, and original import provenance remain.
func UpdateOwner(key, installationID, image []byte, fingerprint, owner string, expectedGeneration uint64) ([]byte, publicinventory.Record, uint64, error) {
	m, existing, err := decode(key, installationID, image)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	if expectedGeneration == 0 || m.Generation != expectedGeneration {
		return nil, publicinventory.Record{}, 0, ErrStaleGeneration
	}
	if m.Generation >= maxGeneration {
		return nil, publicinventory.Record{}, 0, ErrLimit
	}
	if !publicinventory.ValidOwner(owner) {
		return nil, publicinventory.Record{}, 0, publicinventory.ErrLabel
	}
	for i, record := range existing {
		if record.Fingerprint == fingerprint {
			updated, err := publicinventory.UpdateOwner(record, owner)
			if err != nil {
				return nil, publicinventory.Record{}, 0, err
			}
			result, generation, err := resealRecord(key, installationID, m, i, updated)
			if err != nil {
				return nil, publicinventory.Record{}, 0, err
			}
			return result, updated, generation, err
		}
	}
	return nil, publicinventory.Record{}, 0, ErrNotFound
}

// ChangeLocation corrects or removes one exact operator note. The caller must
// atomically install the returned complete image under the writer lock.
func ChangeLocation(key, installationID, image []byte, fingerprint, oldLabel, newLabel string, action LocationChange, expectedGeneration uint64) ([]byte, publicinventory.Record, uint64, error) {
	m, existing, err := decode(key, installationID, image)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	if expectedGeneration == 0 || m.Generation != expectedGeneration {
		return nil, publicinventory.Record{}, 0, ErrStaleGeneration
	}
	if m.Generation >= maxGeneration {
		return nil, publicinventory.Record{}, 0, ErrLimit
	}
	if publicinventory.ValidateLocation(oldLabel) != nil ||
		(action == LocationRename && publicinventory.ValidateLocation(newLabel) != nil) ||
		(action == LocationRemove && newLabel != "") ||
		(action != LocationRename && action != LocationRemove) {
		return nil, publicinventory.Record{}, 0, publicinventory.ErrLabel
	}
	for i, record := range existing {
		if record.Fingerprint != fingerprint {
			continue
		}
		var updated publicinventory.Record
		if action == LocationRename {
			updated, err = publicinventory.RenameLocation(record, oldLabel, newLabel)
		} else {
			updated, err = publicinventory.RemoveLocation(record, oldLabel)
		}
		if err != nil {
			return nil, publicinventory.Record{}, 0, err
		}
		result, generation, err := resealRecord(key, installationID, m, i, updated)
		if err != nil {
			return nil, publicinventory.Record{}, 0, err
		}
		return result, updated, generation, nil
	}
	return nil, publicinventory.Record{}, 0, ErrNotFound
}

// DeleteRecord removes exactly one saved public certificate and its manual
// notes from a fully authenticated image. It cannot erase older snapshots or
// change any deployed certificate. The caller must atomically install the
// returned complete image under the writer lock.
func DeleteRecord(key, installationID, image []byte, fingerprint string, expectedGeneration uint64) ([]byte, uint64, error) {
	m, existing, err := decode(key, installationID, image)
	if err != nil {
		return nil, 0, err
	}
	if expectedGeneration == 0 || m.Generation != expectedGeneration {
		return nil, 0, ErrStaleGeneration
	}
	if m.Generation >= maxGeneration {
		return nil, 0, ErrLimit
	}
	for i, record := range existing {
		if record.Fingerprint != fingerprint {
			continue
		}
		m.Records = append(append([]sealedRecord{}, m.Records[:i]...), m.Records[i+1:]...)
		m.Generation++
		result, err := encode(key, m)
		if err != nil {
			return nil, 0, err
		}
		return result, m.Generation, nil
	}
	return nil, 0, ErrNotFound
}

func resealRecord(key, installationID []byte, m manifest, index int, updated publicinventory.Record) ([]byte, uint64, error) {
	var additional []string
	if len(updated.Locations) > 1 {
		additional = updated.Locations[1:]
	}
	plain, err := json.Marshal(payload{DER: updated.DER, Owner: updated.Owner, Location: updated.Location,
		AdditionalLocations: additional, ImportedAt: updated.ImportedAt, ImportGeneration: updated.ImportGeneration})
	if err != nil {
		return nil, 0, ErrInvalid
	}
	m.Generation++
	id := sha256.Sum256(updated.DER)
	var install [16]byte
	copy(install[:], installationID)
	ciphertext, err := inventoryseal.Seal(key, inventoryseal.Context{InstallationID: install, RecordID: id, Generation: m.Generation}, plain)
	if err != nil {
		return nil, 0, err
	}
	m.Records[index] = sealedRecord{ID: id[:], Generation: m.Generation, Ciphertext: ciphertext}
	result, err := encode(key, m)
	if err != nil {
		return nil, 0, err
	}
	return result, m.Generation, nil
}

func validIdentity(key, id []byte) bool {
	if len(key) != 32 || len(id) != 16 {
		return false
	}
	return !bytes.Equal(id, make([]byte, 16))
}

func encode(key []byte, m manifest) ([]byte, error) {
	body, err := json.Marshal(m)
	if err != nil || len(body) > maxImage {
		return nil, ErrLimit
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(macLabel))
	_, _ = mac.Write(body)
	result, err := json.Marshal(envelope{Body: body, MAC: mac.Sum(nil)})
	if err != nil || len(result) > maxImage {
		return nil, ErrLimit
	}
	return result, nil
}

func decode(key, id, image []byte) (manifest, []publicinventory.Record, error) {
	if !validIdentity(key, id) || len(image) == 0 || len(image) > maxImage {
		return manifest{}, nil, ErrInvalid
	}
	var outer envelope
	if !strictJSON(image, &outer) || len(outer.MAC) != sha256.Size || len(outer.Body) == 0 || len(outer.Body) > maxImage {
		return manifest{}, nil, ErrInvalid
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(macLabel))
	_, _ = mac.Write(outer.Body)
	if !hmac.Equal(mac.Sum(nil), outer.MAC) {
		return manifest{}, nil, ErrInvalid
	}
	var m manifest
	if !strictJSON(outer.Body, &m) || m.Version != 1 || !bytes.Equal(m.InstallationID, id) || m.Generation == 0 || m.Generation > maxGeneration || len(m.Records) > maxRecords || m.Records == nil {
		return manifest{}, nil, ErrInvalid
	}
	var catalog publicinventory.Catalog
	records := make([]publicinventory.Record, 0, len(m.Records))
	for _, item := range m.Records {
		if len(item.ID) != sha256.Size || item.Generation < 2 || item.Generation > m.Generation || len(item.Ciphertext) == 0 {
			return manifest{}, nil, ErrInvalid
		}
		var install [16]byte
		var recordID [32]byte
		copy(install[:], id)
		copy(recordID[:], item.ID)
		plain, err := inventoryseal.Open(key, inventoryseal.Context{InstallationID: install, RecordID: recordID, Generation: item.Generation}, item.Ciphertext)
		if err != nil {
			return manifest{}, nil, ErrInvalid
		}
		var p payload
		if !strictJSON(plain, &p) || len(p.DER) == 0 {
			return manifest{}, nil, ErrInvalid
		}
		if p.ImportedAt != "" {
			parsed, err := time.Parse(time.RFC3339, p.ImportedAt)
			if err != nil || parsed.UTC().Format("2006-01-02T15:04:05Z") != p.ImportedAt {
				return manifest{}, nil, ErrInvalid
			}
		}
		actualID := sha256.Sum256(p.DER)
		if !hmac.Equal(actualID[:], item.ID) {
			return manifest{}, nil, ErrInvalid
		}
		added, err := catalog.Add(p.DER, p.Owner, p.Location)
		if err != nil || len(added) != 1 {
			return manifest{}, nil, ErrInvalid
		}
		if p.Location == "" && len(p.AdditionalLocations) != 0 {
			return manifest{}, nil, ErrInvalid
		}
		record := added[0]
		for _, location := range p.AdditionalLocations {
			record, err = publicinventory.AssociateLocation(record, location)
			if err != nil {
				return manifest{}, nil, ErrInvalid
			}
		}
		if p.ImportGeneration != 0 {
			if p.ImportGeneration < 2 || p.ImportGeneration > item.Generation {
				return manifest{}, nil, ErrInvalid
			}
			record.ImportGeneration = p.ImportGeneration
		} else {
			record.ImportGeneration = item.Generation
		}
		record.ImportedAt = p.ImportedAt
		records = append(records, record)
	}
	if m.Generation == math.MaxUint64 {
		return manifest{}, nil, ErrInvalid
	}
	return m, records, nil
}

func strictJSON(data []byte, target any) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return false
	}
	canonical, err := json.Marshal(target)
	return err == nil && bytes.Equal(canonical, data)
}
