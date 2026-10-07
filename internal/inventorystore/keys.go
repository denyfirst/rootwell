package inventorystore

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func mID(der []byte) []byte { sum := sha256.Sum256(der); return sum[:] }

func attachmentKey(key, id, recordID []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, id, "rootwell.certificate-private-key.v1:"+string(recordID), 32)
}

func attachmentContext(id []byte, item sealedRecord) inventoryseal.Context {
	var c inventoryseal.Context
	copy(c.InstallationID[:], id)
	copy(c.RecordID[:], item.ID)
	c.Generation = item.Generation
	return c
}

func openAttachment(key, id []byte, item sealedRecord) ([]byte, error) {
	k, err := attachmentKey(key, id, item.ID)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(k)
	return inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
}

// authenticateKeys checks every attachment before any public output. Parsed
// secrets are not retained by records or the manifest, even during listing.
func authenticateKeys(key, id []byte, m manifest, records []publicinventory.Record) error {
	if len(m.Keys) > len(records) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, item := range m.Keys {
		if len(item.ID) != 32 || item.Generation < 2 || item.Generation > m.Generation || seen[string(item.ID)] {
			return ErrInvalid
		}
		seen[string(item.ID)] = true
		index := -1
		for i, r := range records {
			if bytes.Equal(item.ID, mID(r.DER)) {
				index = i
				break
			}
		}
		if index < 0 {
			return ErrInvalid
		}
		plain, err := openAttachment(key, id, item)
		if err != nil {
			return ErrInvalid
		}
		valid := len(plain) > 0 && len(plain) <= 64<<10 && keymatch.WithMatchedKey(records[index].DER, plain,
			func(cert *x509.Certificate, k any) error {
				if cert.IsCA {
					return ErrInvalid
				}
				canonical, err := x509.MarshalPKCS8PrivateKey(k)
				defer clear(canonical)
				if err != nil || !bytes.Equal(canonical, plain) {
					return ErrInvalid
				}
				return nil
			}) == nil
		clear(plain)
		if !valid {
			return ErrInvalid
		}
		records[index].HasPrivateKey = true
		records[index].KeyStatus = "matched"
	}
	return nil
}

// AppendCertificate atomically prepares a public record and optional matched
// key in one image. The displayed generation is mandatory, even without a key.
func AppendCertificate(key, id, image, certificate, privateKey, password []byte, owner, location, fingerprint string, expected uint64) ([]byte, publicinventory.Record, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	if expected == 0 || m.Generation != expected {
		return nil, publicinventory.Record{}, 0, ErrStaleGeneration
	}
	r, canonical, err := certificatepair.Prepare(certificate, privateKey, password, owner, location)
	defer clear(canonical)
	if err != nil || r.Fingerprint != fingerprint {
		return nil, publicinventory.Record{}, 0, certificatepair.ErrInvalid
	}
	next, added, err := Append(key, id, image, r.DER, owner, location)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	if len(canonical) == 0 {
		return next, added[0], expected + 1, nil
	}
	m, _, err = decode(key, id, next)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	item := sealedRecord{ID: mID(r.DER), Generation: m.Generation}
	k, err := attachmentKey(key, id, item.ID)
	if err != nil {
		return nil, publicinventory.Record{}, 0, ErrInvalid
	}
	defer clear(k)
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), canonical)
	if err != nil {
		return nil, publicinventory.Record{}, 0, ErrInvalid
	}
	m.Keys = append(m.Keys, item)
	result, err := encode(key, m)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	// Revalidate before the writer is allowed to commit.
	_, records, err := decode(key, id, result)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	return result, records[len(records)-1], m.Generation, nil
}

// WithCertificate lends a public certificate and optional key at an exact
// generation. Secret delivery policy and reauthentication belong to the caller.
// The callback must not retain the key bytes. ADR 0047 material may contain a
// loose mismatched key: consumers MUST require KeyStatus == "matched" before
// any pair/PFX/CSR/deployment operation; key-only export is separately gated.
func WithCertificate(key, id, image []byte, fingerprint string, expected uint64, use func(publicinventory.Record, []byte) error) error {
	m, records, err := decode(key, id, image)
	if err != nil {
		return err
	}
	if expected == 0 || expected != m.Generation {
		return ErrStaleGeneration
	}
	if use == nil {
		return ErrInvalid
	}
	for _, r := range records {
		if r.Fingerprint != fingerprint {
			continue
		}
		for _, item := range m.Materials {
			if !bytes.Equal(item.ID, mID(r.DER)) {
				continue
			}
			material, err := openMaterial(key, id, item)
			if err != nil {
				return ErrInvalid
			}
			defer clear(material.PrivateKey)
			return use(r, material.PrivateKey)
		}
		for _, item := range m.Keys {
			if !bytes.Equal(item.ID, mID(r.DER)) {
				continue
			}
			plain, err := openAttachment(key, id, item)
			if err != nil {
				return ErrInvalid
			}
			defer clear(plain)
			return use(r, plain)
		}
		return use(r, nil)
	}
	return ErrNotFound
}
