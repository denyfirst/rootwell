package inventorystore

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

type materialPayload struct {
	Certificates         [][]byte `json:"certificates"`
	PrivateKey           []byte   `json:"private_key,omitempty"`
	MismatchAcknowledged bool     `json:"mismatch_acknowledged,omitempty"`
}

func materialKey(key, id, recordID []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, id, "rootwell.certificate-material.v1:"+string(recordID), 32)
}
func openMaterial(key, id []byte, item sealedRecord) (materialPayload, error) {
	var p materialPayload
	k, err := materialKey(key, id, item.ID)
	if err != nil {
		return p, ErrInvalid
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	defer clear(plain)
	if err != nil || !strictJSON(plain, &p) {
		clear(p.PrivateKey)
		return materialPayload{}, ErrInvalid
	}
	return p, nil
}
func authenticateMaterials(key, id []byte, m manifest, records []publicinventory.Record) error {
	if len(m.Materials)+len(m.Keys) > len(records) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, item := range m.Keys {
		seen[string(item.ID)] = true
	}
	for _, item := range m.Materials {
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
		p, err := openMaterial(key, id, item)
		if err != nil {
			return ErrInvalid
		}
		if len(p.Certificates) == 0 || len(p.Certificates) > certificatepair.MaxBundleCertificates {
			clear(p.PrivateKey)
			return ErrInvalid
		}
		total := 0
		for _, der := range p.Certificates {
			if len(der) == 0 || len(der) > 64<<10 {
				clear(p.PrivateKey)
				return ErrInvalid
			}
			total += len(der)
		}
		if total > 512<<10 {
			clear(p.PrivateKey)
			return ErrInvalid
		}
		input := certificatepair.PublicPEM(p.Certificates)
		r, canonical, err := certificatepair.PrepareBundle(input, p.PrivateKey, nil, "", "", records[index].Fingerprint)
		// Explicit mismatch acceptance is sealed together with the actual key;
		// it never removes parsing, identity or issuer-signature validation.
		valid := err == nil && bytes.Equal(canonical, p.PrivateKey) && (r.KeyStatus == "mismatch") == p.MismatchAcknowledged
		clear(canonical)
		clear(p.PrivateKey)
		clear(input)
		if !valid {
			return ErrInvalid
		}
		records[index].HasPrivateKey = r.HasPrivateKey
		records[index].KeyStatus = r.KeyStatus
		records[index].BundleDER = r.BundleDER
		records[index].IssuerDER = r.IssuerDER
	}
	return nil
}

// AppendMaterial always recomputes selection and match under the writer's
// generation precondition. An acknowledgement is required only for mismatch.
func AppendMaterial(key, id, image, input, private, password []byte, owner, location, selected string, ack bool, expected uint64) ([]byte, publicinventory.Record, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, publicinventory.Record{}, 0, ErrStaleGeneration
	}
	r, canonical, err := certificatepair.PrepareBundle(input, private, password, owner, location, selected)
	defer clear(canonical)
	if err != nil || (r.KeyStatus == "mismatch" && !ack) || (r.KeyStatus != "mismatch" && ack) {
		return nil, publicinventory.Record{}, 0, certificatepair.ErrInvalid
	}
	next, _, err := Append(key, id, image, r.DER, owner, location)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	m, _, err = decode(key, id, next)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	p := materialPayload{Certificates: r.BundleDER, PrivateKey: canonical, MismatchAcknowledged: ack}
	// Secret serialization is an internal encryption boundary, never output.
	plain, err := json.Marshal(p) // #nosec G117 -- immediately AES-GCM sealed below; owned plaintext cleared, never logged or returned
	defer clear(plain)
	if err != nil {
		return nil, publicinventory.Record{}, 0, ErrInvalid
	}
	item := sealedRecord{ID: mID(r.DER), Generation: m.Generation}
	k, err := materialKey(key, id, item.ID)
	if err != nil {
		return nil, publicinventory.Record{}, 0, ErrInvalid
	}
	defer clear(k)
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	m.Materials = append(m.Materials, item)
	result, err := encode(key, m)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	_, records, err := decode(key, id, result)
	if err != nil {
		return nil, publicinventory.Record{}, 0, err
	}
	return result, records[len(records)-1], m.Generation, nil
}
