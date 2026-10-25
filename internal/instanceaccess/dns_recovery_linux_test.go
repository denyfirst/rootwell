//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

// Synthetic custody fixture only: authenticate a valid exhausted state without
// waiting through sixteen minutes of production backoff. Model tests separately
// exercise all six real transitions. No runtime clock/credential seam is added.
func exhaustSyntheticDNS(t *testing.T, path string, key, id []byte) uint64 {
	t.Helper()
	store := filepath.Join(filepath.Dir(path), inventoryName)
	image, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	var outer struct {
		Body []byte `json:"body"`
		MAC  []byte `json:"mac"`
	}
	if json.Unmarshal(image, &outer) != nil {
		t.Fatal("fixture envelope")
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(outer.Body, &body) != nil {
		t.Fatal("fixture body")
	}
	var plans []struct {
		ID         []byte `json:"id"`
		Generation uint64 `json:"generation"`
		Ciphertext []byte `json:"ciphertext"`
	}
	if json.Unmarshal(body["dns_plans"], &plans) != nil || len(plans) != 1 {
		t.Fatal("fixture plan")
	}
	k, err := hkdf.Key(sha256.New, key, id, "rootwell.acme-dns-plan-key.v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(k)
	var context inventoryseal.Context
	copy(context.InstallationID[:], id)
	copy(context.RecordID[:], plans[0].ID)
	context.Generation = plans[0].Generation
	plain, err := inventoryseal.Open(k, context, plans[0].Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	var p map[string]json.RawMessage
	if json.Unmarshal(plain, &p) != nil {
		t.Fatal("fixture payload")
	}
	var rows []map[string]json.RawMessage
	if json.Unmarshal(p["records"], &rows) != nil {
		t.Fatal("fixture records")
	}
	var retry providerretry.State
	if json.Unmarshal(rows[0]["retry"], &retry) != nil {
		t.Fatal("fixture retry")
	}
	last, err := time.Parse("2006-01-02T15:04:05Z", retry.LastAt)
	if err != nil {
		t.Fatal(err)
	}
	retry.Attempts = 6
	retry.NotBefore = last.Add(time.Second).Format("2006-01-02T15:04:05Z")
	rows[0]["retry"], err = json.Marshal(retry)
	if err != nil {
		t.Fatal(err)
	}
	p["records"], err = json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	plans[0].Ciphertext, err = inventoryseal.Seal(k, context, plain)
	if err != nil {
		t.Fatal(err)
	}
	body["dns_plans"], err = json.Marshal(plans)
	if err != nil {
		t.Fatal(err)
	}
	outer.Body, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("rootwell.public-inventory.manifest.v1:"))
	_, _ = mac.Write(outer.Body)
	outer.MAC = mac.Sum(nil)
	image, err = json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	_, gen, err := inventorystore.ReadStagingDNSPlan(key, id, image)
	if err != nil {
		t.Fatal("synthetic exhausted state invalid", err)
	}
	if err := withAccessWriteLock(path, func() error { return replaceInventory(store, image) }); err != nil {
		t.Fatal(err)
	}
	if wait := time.Until(last.Add(time.Second)); wait > 0 {
		time.Sleep(wait)
	}
	return gen
}

func TestLinuxDNSRecoveryLockedReadOnlyAndFullRestore(t *testing.T) {
	path, password, code, key, id, revision := dnsPlanStoreFixture(t)
	defer clear(key)
	_, _, err := RunStagingDNS(path, key, id, revision, 8, 0, "add", func() bool { return true }, func(_ func() bool, _ []byte, _ dnsrecord.Scope, _ dnsrecord.State, _, _ bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		if err := checkpoint(dnsrecord.State{State: "creating"}); err != nil {
			t.Fatal(err)
		}
		return dnsrecord.State{}, errors.New("synthetic-lost-create")
	})
	if err != nil {
		t.Fatal(err)
	}
	gen := exhaustSyntheticDNS(t, path, key, id)
	var borrowed []byte
	result, g, err := RunStagingDNS(path, key, id, revision, gen, 0, "recover", func() bool { return true }, func(permit func() bool, token []byte, _ dnsrecord.Scope, saved dnsrecord.State, cleanup, read bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		borrowed = token
		if !permit() || !read || cleanup || saved.State != "creating" {
			t.Fatal("recovery gained create/delete")
		}
		if _, _, err := ReadStagingDNSPlan(path, key, id, revision); !errors.Is(err, ErrAccessBusy) {
			t.Fatal("recovery released writer lock")
		}
		if err := checkpoint(saved); err == nil {
			t.Fatal("recovery gained mutation checkpoint")
		}
		pending, _ := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		s, _, err := inventorystore.ReadStagingDNSPlan(key, id, pending)
		if err != nil || s.Records[0].Recovery == nil || s.Records[0].Recovery.Attempts != 1 {
			t.Fatal("network before durable recovery intent")
		}
		return dnsrecord.State{}, &providerretry.Failure{Hint: providerretry.Hint{NotBefore: time.Now().UTC().Add(6 * time.Hour)}}
	})
	if err != nil || g != gen+2 || result.Records[0].Attempts != 6 || result.Records[0].Recovery == nil {
		t.Fatal("recovery result", err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed token not cleared")
	}
	backup := filepath.Join(privateSnapshotDir(t), "dns-recovery.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	for _, unlock := range []SnapshotUnlock{SnapshotPassword, SnapshotRecoveryCode} {
		fresh := filepath.Join(privateSnapshotDir(t), "access.json")
		credential := password
		if unlock == SnapshotRecoveryCode {
			credential = code
		}
		if err := RestoreFullSnapshot(backup, fresh, credential, unlock); err != nil {
			t.Fatal(err)
		}
		const recovered = "a separate sufficiently long read only DNS recovery password"
		if _, err := RecoverPassword(fresh, code, recovered); err != nil {
			t.Fatal(err)
		}
		k, identity, err := OpenWithIdentity(fresh, recovered)
		if err != nil {
			t.Fatal(err)
		}
		rev, err := Revision(fresh)
		if err != nil {
			t.Fatal(err)
		}
		s, got, err := ReadStagingDNSPlan(fresh, k, identity, rev)
		if err != nil || got != g || s.Records[0].Attempts != 6 || s.Records[0].Recovery == nil || *s.Records[0].Recovery != *result.Records[0].Recovery {
			t.Fatal("restore reset recovery", err)
		}
		if _, _, err := RunStagingDNS(fresh, k, identity, rev, g, 0, "recover", func() bool { return true }, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
			t.Fatal("restore skipped durable wait")
			return dnsrecord.State{}, nil
		}); err == nil {
			t.Fatal("restored early recovery accepted")
		}
		clear(k)
	}
}
