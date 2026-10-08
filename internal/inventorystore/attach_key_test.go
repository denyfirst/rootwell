package inventorystore

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/denyfirst/rootwell/internal/publicinventory"
	"github.com/youmark/pkcs8"
)

func TestAttachKeyPreservesRecordAndRefusesOverwrite(t *testing.T) {
	key, id := testIdentity(t)
	cert, private, fp := generatedPair(t)
	defer clear(private)
	_, wrong, _ := generatedPair(t)
	defer clear(wrong)
	for _, material := range []bool{false, true} {
		image, _ := Create(key, id)
		if material {
			image, _, _, _ = AppendMaterial(key, id, image, cert, nil, nil, "Team", "Nginx", fp, false, 1)
		} else {
			image, _, _ = Append(key, id, image, cert, "Team", "Nginx")
		}
		before := bytes.Clone(image)
		r, canonical, err := PrepareKeyAttachment(key, id, image, private, nil, fp, 2)
		if err != nil || r.KeyStatus != "matched" || !bytes.Equal(canonical, private) || !bytes.Equal(image, before) {
			t.Fatal("valid preview failed or mutated image")
		}
		clear(canonical)
		original, _, _ := Open(key, id, image)
		for _, attempt := range []struct {
			private  []byte
			ack      bool
			expected uint64
			fp       string
		}{
			{wrong, false, 2, fp}, {private, true, 2, fp}, {nil, false, 2, fp}, {[]byte("secret-sentinel"), true, 2, fp}, {private, false, 1, fp}, {private, false, 0, fp}, {private, false, 2, "unknown"},
		} {
			next, _, gen, err := AttachKey(key, id, image, attempt.private, nil, attempt.fp, attempt.ack, attempt.expected)
			if err == nil || len(next) != 0 || gen != 0 || !bytes.Equal(image, before) {
				t.Fatal("invalid attachment wrote or returned partial image")
			}
		}
		next, updated, gen, err := AttachKey(key, id, image, private, nil, fp, false, 2)
		if err != nil || gen != 3 || updated.KeyStatus != "matched" || updated.Owner != original[0].Owner || updated.Location != original[0].Location || updated.ImportedAt != original[0].ImportedAt || updated.ImportGeneration != original[0].ImportGeneration {
			t.Fatal("attachment changed public provenance or refused valid key")
		}
		m, records, err := decode(key, id, next)
		if err != nil || len(records) != 1 || len(m.Materials) != 1 {
			t.Fatal("attachment duplicated record or material")
		}
		public, _ := json.Marshal(records)
		if bytes.Contains(next, []byte(base64.StdEncoding.EncodeToString(private))) || bytes.Contains(public, []byte(base64.StdEncoding.EncodeToString(private))) {
			t.Fatal("key escaped encrypted attachment")
		}
		events, _, err := History(key, id, next)
		if err != nil || events[len(events)-1].Action != "key-added" || events[len(events)-1].Generation != 3 {
			t.Fatal("key event missing")
		}
		for _, replacement := range [][]byte{private, wrong} {
			bad, _, _, err := AttachKey(key, id, next, replacement, nil, fp, !bytes.Equal(replacement, private), 3)
			if !errors.Is(err, ErrKeyExists) || len(bad) != 0 {
				t.Fatal("existing key overwritten")
			}
		}
		changed, r, _, err := UpdateOwner(key, id, next, fp, "New team", 3)
		if err != nil || r.KeyStatus != "matched" {
			t.Fatal("note edit lost key")
		}
		if err := WithCertificate(key, id, changed, fp, 4, func(_ publicinventory.Record, k []byte) error {
			if !bytes.Equal(k, private) {
				t.Fatal("attached key changed")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		deleted, _, err := DeleteRecord(key, id, changed, fp, 4)
		if err != nil {
			t.Fatal(err)
		}
		m, _, err = decode(key, id, deleted)
		if err != nil || len(m.Materials) != 0 {
			t.Fatal("deleted key orphaned")
		}
		loose, r, _, err := AttachKey(key, id, image, wrong, nil, fp, true, 2)
		if err != nil || r.KeyStatus != "mismatch" {
			t.Fatal("explicit loose attachment refused")
		}
		if _, _, err := Open(key, id, loose); err != nil {
			t.Fatal("loose image cannot reopen")
		}
		corrupt := bytes.Clone(image)
		corrupt[len(corrupt)/2] ^= 1
		if bad, _, _, err := AttachKey(key, id, corrupt, private, nil, fp, false, 2); err == nil || len(bad) != 0 {
			t.Fatal("unauthenticated image changed")
		}
	}
}

func TestAttachEncryptedKeyAndCapacityRefusals(t *testing.T) {
	key, id := testIdentity(t)
	cert, private, fp := generatedPair(t)
	defer clear(private)
	parsed, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		t.Fatal("synthetic key parsing failed")
	}
	password := []byte("synthetic-key-password-only")
	protected, err := pkcs8.MarshalPrivateKey(parsed, password, &pkcs8.Opts{Cipher: pkcs8.AES256CBC, KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 600000, HMACHash: crypto.SHA256}})
	if err != nil {
		t.Fatal("synthetic key encryption failed")
	}
	defer clear(protected)
	image, err := Create(key, id)
	if err != nil {
		t.Fatal(err)
	}
	image, _, err = Append(key, id, image, cert, "Team", "Nginx")
	if err != nil {
		t.Fatal(err)
	}
	second, _, _ := generatedPair(t)
	image, _, err = Append(key, id, image, second, "Another team", "Other service")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct{ key, password []byte }{{protected, nil}, {protected, []byte("secret-sentinel-wrong")}, {private, make([]byte, 257)}, {make([]byte, 64*1024+1), nil}} {
		if output, _, _, err := AttachKey(key, id, image, input.key, input.password, fp, false, 3); err == nil || len(output) != 0 {
			t.Fatal("invalid password or oversized key accepted")
		}
	}
	next, _, _, err := AttachKey(key, id, image, protected, password, fp, false, 3)
	if err != nil {
		t.Fatal("encrypted key attachment refused")
	}
	records, gen, err := Open(key, id, next)
	if err != nil || gen != 4 || len(records) != 2 || records[0].Fingerprint != fp || !records[0].HasPrivateKey || records[1].HasPrivateKey || records[1].Owner != "Another team" {
		t.Fatal("attachment changed order or other record")
	}
	if err := WithCertificate(key, id, next, fp, 4, func(_ publicinventory.Record, k []byte) error {
		if !bytes.Equal(k, private) {
			t.Fatal("encrypted input did not preserve canonical key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	for len(m.History) < maxHistory {
		m.Generation++
		if err := addEvent(key, &m, "owner-changed", []string{fp}); err != nil {
			t.Fatal(err)
		}
	}
	full, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	if output, _, _, err := AttachKey(key, id, full, private, nil, fp, false, m.Generation); !errors.Is(err, ErrLimit) || len(output) != 0 {
		t.Fatal("attachment truncated full history")
	}
	// Legacy no-history image at the common generation ceiling is still readable.
	m.History = nil
	m.Generation = maxGeneration
	full, err = encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(key, id, full); err != nil {
		t.Fatal("valid generation ceiling image refused")
	}
	if output, _, _, err := AttachKey(key, id, full, private, nil, fp, false, maxGeneration); !errors.Is(err, ErrLimit) || len(output) != 0 {
		t.Fatal("attachment wrapped generation ceiling")
	}
}
