package inventoryseal

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func testContext() Context {
	var context Context
	context.InstallationID[0] = 1
	context.RecordID[0] = 2
	context.Generation = 1
	return context
}

func testKey() []byte { return bytes.Repeat([]byte{0x42}, keySize) }

func TestSealRoundTripUsesFreshNonceAndHidesPlaintext(t *testing.T) {
	key := testKey()
	context := testContext()
	plaintext := []byte(`{"owner":"internal-platform-team","location":"production-edge"}`)
	a, err := Seal(key, context, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(key, context, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) || bytes.Contains(a, plaintext) || bytes.Contains(b, plaintext) {
		t.Fatal("record encryption is deterministic or leaks plaintext")
	}
	for _, record := range [][]byte{a, b} {
		opened, err := Open(key, context, record)
		if err != nil || !bytes.Equal(opened, plaintext) {
			t.Fatalf("round trip failed: %v", err)
		}
	}
	plaintext[0] = 'X'
	opened, err := Open(key, context, a)
	if err != nil || opened[0] != '{' {
		t.Fatal("sealed record changed after source mutation")
	}
}

func TestSealRejectsWrongKeyContextSwapAndTampering(t *testing.T) {
	key := testKey()
	context := testContext()
	record, err := Seal(key, context, []byte("public certificate metadata"))
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := bytes.Clone(key)
	wrongKey[0] ^= 1
	if _, err := Open(wrongKey, context, record); !errors.Is(err, ErrRecord) {
		t.Fatalf("wrong key opened record: %v", err)
	}
	changed := context
	changed.InstallationID[0]++
	if _, err := Open(key, changed, record); !errors.Is(err, ErrRecord) {
		t.Fatalf("record moved to another installation: %v", err)
	}
	changed = context
	changed.RecordID[0]++
	if _, err := Open(key, changed, record); !errors.Is(err, ErrRecord) {
		t.Fatalf("record moved to another certificate: %v", err)
	}
	changed = context
	changed.Generation++
	if _, err := Open(key, changed, record); !errors.Is(err, ErrRecord) {
		t.Fatalf("record replayed at another generation: %v", err)
	}
	for _, offset := range []int{0, len(magic), len(record) / 2, len(record) - 1} {
		tampered := bytes.Clone(record)
		tampered[offset] ^= 1
		if opened, err := Open(key, context, tampered); !errors.Is(err, ErrRecord) || opened != nil {
			t.Fatalf("tamper at %d was accepted: %v", offset, err)
		}
	}
	for _, malformed := range [][]byte{
		nil, record[:len(record)-1], append(bytes.Clone(record), 0),
		bytes.Repeat([]byte{0x41}, len(magic)+sealOverhead+maxPlaintext+1),
	} {
		if opened, err := Open(key, context, malformed); !errors.Is(err, ErrRecord) || opened != nil {
			t.Fatalf("malformed record was accepted: %v", err)
		}
	}
}

func TestSealBoundsAndMissingContextFailClosed(t *testing.T) {
	key := testKey()
	context := testContext()
	for _, invalidKey := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte{1}, 16)} {
		if _, err := Seal(invalidKey, context, []byte("data")); !errors.Is(err, ErrKey) {
			t.Fatalf("invalid key accepted: %v", err)
		}
		if _, err := Open(invalidKey, context, []byte("data")); !errors.Is(err, ErrKey) {
			t.Fatalf("invalid open key accepted: %v", err)
		}
	}
	for _, invalidContext := range []Context{
		{},
		{InstallationID: context.InstallationID, RecordID: context.RecordID},
		{RecordID: context.RecordID, Generation: 1},
		{InstallationID: context.InstallationID, Generation: 1},
	} {
		if _, err := Seal(key, invalidContext, []byte("data")); !errors.Is(err, ErrContext) {
			t.Fatalf("missing context accepted: %v", err)
		}
		if _, err := Open(key, invalidContext, []byte("RWINV001")); !errors.Is(err, ErrContext) {
			t.Fatalf("missing open context accepted: %v", err)
		}
	}
	for _, plaintext := range [][]byte{nil, bytes.Repeat([]byte{1}, maxPlaintext+1)} {
		if _, err := Seal(key, context, plaintext); !errors.Is(err, ErrSize) {
			t.Fatalf("invalid plaintext size accepted: %v", err)
		}
	}
	full, err := Seal(key, context, bytes.Repeat([]byte{1}, maxPlaintext))
	if err != nil {
		t.Fatalf("maximum permitted plaintext rejected: %v", err)
	}
	opened, err := Open(key, context, full)
	if err != nil || len(opened) != maxPlaintext {
		t.Fatalf("maximum permitted record failed to open: %v", err)
	}
}

func FuzzOpenSealedRecord(f *testing.F) {
	key := testKey()
	context := testContext()
	valid, err := Seal(key, context, []byte("bounded public metadata"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("RWINV001"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		opened, err := Open(key, context, input)
		if err == nil && (len(opened) == 0 || len(opened) > maxPlaintext) {
			t.Fatal("open returned an out-of-bounds plaintext")
		}
	})
}

func TestSealWorksWithRandomDataKey(t *testing.T) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	context := testContext()
	record, err := Seal(key, context, []byte("owner=ops"))
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(key, context, record); err != nil || string(opened) != "owner=ops" {
		t.Fatalf("random key roundtrip: %v", err)
	}
}
