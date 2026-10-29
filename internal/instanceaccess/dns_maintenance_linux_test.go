//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

// Test-only rebase of a synthetic credential/order/history fixture. No clock
// override, import route or runtime receipt authority is added to the daemon.
func pastSyntheticDNS(t *testing.T, path string, key, id []byte) uint64 {
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
	var fields map[string]json.RawMessage
	if json.Unmarshal(outer.Body, &fields) != nil {
		t.Fatal("fixture fields")
	}
	times := regexp.MustCompile(`20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z`)
	for _, collection := range []struct{ name, label string }{
		{"acme_accounts", "rootwell.acme-account-key.v1:letsencrypt-staging"}, {"acme_orders", "rootwell.acme-staging-order-key.v1"}, {"cloudflare_configs", "rootwell.dns-cloudflare-config-key.v1"}, {"dns_plans", "rootwell.acme-dns-plan-key.v1"}, {"history", ""},
	} {
		original := fields[collection.name]
		if len(original) == 0 {
			t.Fatal("missing synthetic collection", collection.name)
		}
		var entries []struct {
			ID         []byte `json:"id"`
			Generation uint64 `json:"generation"`
			Ciphertext []byte `json:"ciphertext"`
		}
		if json.Unmarshal(original, &entries) != nil {
			t.Fatal("fixture sealed entries")
		}
		k := bytes.Clone(key)
		if collection.label != "" {
			clear(k)
			k, err = hkdf.Key(sha256.New, key, id, collection.label, 32)
			if err != nil {
				t.Fatal(err)
			}
		}
		for i := range entries {
			e := &entries[i]
			var c inventoryseal.Context
			copy(c.InstallationID[:], id)
			copy(c.RecordID[:], e.ID)
			c.Generation = e.Generation
			if collection.name == "history" {
				c.RecordID = sha256.Sum256([]byte("rootwell.history.event.v1:" + strconv.FormatUint(e.Generation, 10)))
			}
			plain, err := inventoryseal.Open(k, c, e.Ciphertext)
			if err != nil {
				clear(k)
				t.Fatal("synthetic collection open", collection.name)
			}
			shifted := times.ReplaceAllFunc(plain, func(b []byte) []byte {
				at, err := time.Parse(time.RFC3339, string(b))
				if err != nil {
					t.Fatal(err)
				}
				return []byte(at.Add(-8 * 24 * time.Hour).Format(time.RFC3339))
			})
			clear(plain)
			e.Ciphertext, err = inventoryseal.Seal(k, c, shifted)
			clear(shifted)
			if err != nil {
				clear(k)
				t.Fatal(err)
			}
		}
		clear(k)
		encoded, err := json.Marshal(entries)
		if err != nil || bytes.Count(outer.Body, original) != 1 {
			t.Fatal("ambiguous synthetic splice")
		}
		outer.Body = bytes.Replace(outer.Body, original, encoded, 1)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("rootwell.public-inventory.manifest.v1:"))
	_, _ = mac.Write(outer.Body)
	outer.MAC = mac.Sum(nil)
	image, err = json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	s, g, err := inventorystore.ReadStagingDNSPlan(key, id, image)
	if err != nil || s.Records[0].Maintenance == nil || s.Records[0].Maintenance.NotBefore > time.Now().UTC().Format(time.RFC3339) {
		t.Fatal("past synthetic fixture refused", err)
	}
	if err := replaceInventory(store, image); err != nil {
		t.Fatal(err)
	}
	return g
}

func maintenanceStore(t *testing.T) (string, string, string, []byte, []byte, [32]byte, uint64) {
	t.Helper()
	path, password, code, key, id, revision := dnsPlanStoreFixture(t)
	_, _, err := RunStagingDNS(path, key, id, revision, 8, 0, "add", func() bool { return true }, func(_ func() bool, _ []byte, _ dnsrecord.Scope, _ dnsrecord.State, _ bool, _ bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		if err := checkpoint(dnsrecord.State{State: "creating"}); err != nil {
			return dnsrecord.State{}, err
		}
		return dnsrecord.State{}, &providerretry.Failure{Hint: providerretry.Hint{Blocked: true}}
	})
	if err != nil {
		t.Fatal(err)
	}
	g := pastSyntheticDNS(t, path, key, id)
	return path, password, code, key, id, revision, g
}

func TestLinuxDNSMaintenanceReadOnlyIntentFullRestoreAndNoOrdinaryAuthority(t *testing.T) {
	path, password, code, key, id, rev, g := maintenanceStore(t)
	defer clear(key)
	called := false
	if _, _, err := RunStagingDNS(path, key, id, rev, g, 0, "maintenance", func() bool { return true }, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
		called = true
		return dnsrecord.State{}, nil
	}); err == nil || called {
		t.Fatal("ordinary capability invoked operator maintenance")
	}
	if _, _, err := RunOperatorDNSMaintenance(path, key, id, rev, g, 0, func() bool { return false }, nil); err == nil {
		t.Fatal("revoked grant admitted")
	}
	var borrowed []byte
	s, ng, err := RunOperatorDNSMaintenance(path, key, id, rev, g, 0, func() bool { return true }, func(permit func() bool, token []byte, _ dnsrecord.Scope, saved dnsrecord.State, cleanup, read bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		borrowed = token
		if !permit() || cleanup || !read || saved.State != "creating" || checkpoint(saved) == nil {
			t.Fatal("maintenance acquired mutation")
		}
		if _, _, err := ReadStagingDNSPlan(path, key, id, rev); !errors.Is(err, ErrAccessBusy) {
			t.Fatal("maintenance lost private writer lock")
		}
		image, _ := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
		pending, pg, err := inventorystore.ReadStagingDNSPlan(key, id, image)
		if err != nil || pg != g+1 || pending.Records[0].Maintenance.Attempts != 1 {
			t.Fatal("provider reached before durable intent")
		}
		return saved, nil
	})
	if err != nil || ng != g+2 || s.Records[0].State != "creating" || s.Records[0].Attempts != 1 || !s.Records[0].Blocked || s.Records[0].Maintenance.Attempts != 1 {
		t.Fatal("maintenance reset terminal policy", err)
	}
	for _, b := range borrowed {
		if b != 0 {
			t.Fatal("borrowed token retained")
		}
	}
	backup := filepath.Join(privateSnapshotDir(t), "operator-dns.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); err != nil {
		t.Fatal(err)
	}
	k, install, err := OpenWithIdentity(fresh, password)
	defer clear(k)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := Revision(fresh)
	restored, rg, err := ReadStagingDNSPlan(fresh, k, install, r)
	if err != nil || rg != ng || restored.Records[0].Maintenance.NotBefore != s.Records[0].Maintenance.NotBefore || !restored.Records[0].Blocked {
		t.Fatal("restore reset manual observation", err)
	}
	if _, _, err := RunOperatorDNSMaintenance(fresh, k, install, r, rg, 0, func() bool { return true }, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
		t.Fatal("restored wait bypassed")
		return dnsrecord.State{}, nil
	}); err == nil {
		t.Fatal("restored observation repeated early")
	}
}

func TestGenerateOperatorDNSGateFixture(t *testing.T) {
	destination := os.Getenv("ROOTWELL_OPERATOR_DNS_FIXTURE")
	if destination == "" {
		t.Skip("private fixture not requested")
	}
	if !filepath.IsAbs(destination) || filepath.Base(destination) != "synthetic-operator-dns.json" {
		t.Fatal("fixture destination refused")
	}
	path, _, _, key, _, _, _ := maintenanceStore(t)
	defer clear(key)
	access, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(access)
	image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(image)
	body, err := json.Marshal(struct{ Access, Image []byte }{access, image})
	defer clear(body)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(body); err != nil {
		t.Fatal(err)
	}
}
