//go:build linux

package instanceaccess

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func TestLinuxDNSOperationIntentLockAuthorityAndFullRecovery(t *testing.T) {
	path, password, code, key, id, revision := dnsPlanStoreFixture(t)
	defer clear(key)
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, _ := readInventory(store)
	refused := func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
		t.Fatal("refused operation borrowed token")
		return dnsrecord.State{}, nil
	}
	for _, tc := range []struct {
		revision [32]byte
		gen      uint64
		index    int
		mode     string
		permit   func() bool
	}{{revision, 7, 0, "add", func() bool { return true }}, {[32]byte{}, 8, 0, "add", func() bool { return true }}, {revision, 8, 8, "add", func() bool { return true }}, {revision, 8, 0, "check", func() bool { return true }}, {revision, 8, 0, "add", nil}} {
		if s, g, err := RunStagingDNS(path, key, id, tc.revision, tc.gen, tc.index, tc.mode, tc.permit, refused); err == nil || s.Prepared || g != 0 {
			t.Fatal("invalid writer scope authorized")
		}
		after, _ := readInventory(store)
		if !bytes.Equal(before, after) {
			t.Fatal("refusal changed image")
		}
	}
	var borrowed []byte
	s, g, err := RunStagingDNS(path, key, id, revision, 8, 0, "add", func() bool { return true }, func(permit func() bool, token []byte, scope dnsrecord.Scope, saved dnsrecord.State, cleanup, readOnly bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		borrowed = token
		if !permit() || string(token) != localDNSToken || scope.ZoneID != localDNSZoneID || scope.Owner == "" || scope.Value == "" || saved.State != "new" || cleanup || readOnly {
			t.Fatal("wrong secret/scope")
		}
		image, _ := readInventory(store)
		pending, gen, err := inventorystore.ReadStagingDNSPlan(key, id, image)
		if err != nil || gen != 10 || pending.Records[0].State != "creating" || pending.Records[0].Attempts != 1 {
			t.Fatal("I/O before durable intent")
		}
		if _, _, err := ReadStagingDNSPlan(path, key, id, revision); !errors.Is(err, ErrAccessBusy) {
			t.Fatal("writer lock released during secret/network use")
		}
		if err := checkpoint(dnsrecord.State{State: "creating"}); err != nil {
			t.Fatal(err)
		}
		return dnsrecord.State{State: "created", ID: strings.Repeat("c", 32)}, nil
	})
	if err != nil || g != 11 || s.Records[0].State != "created" {
		t.Fatal("real writer result failed", err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed token bytes retained")
	}
	if info, err := os.Stat(store); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("unsafe result file")
	}
	image, _ := readInventory(store)
	backup := filepath.Join(privateSnapshotDir(t), "dns-owned.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		credential string
		method     SnapshotUnlock
	}{{password, SnapshotPassword}, {code, SnapshotRecoveryCode}} {
		fresh := filepath.Join(privateSnapshotDir(t), "access.json")
		if err := RestoreFullSnapshot(backup, fresh, tc.credential, tc.method); err != nil {
			t.Fatal(err)
		}
		const recovered = "a separate sufficiently long DNS operation recovery password"
		if _, err := RecoverPassword(fresh, code, recovered); err != nil {
			t.Fatal(err)
		}
		nk, ni, err := OpenWithIdentity(fresh, recovered)
		if err != nil {
			t.Fatal(err)
		}
		rev, _ := Revision(fresh)
		status, gen, err := ReadStagingDNSPlan(fresh, nk, ni, rev)
		if err != nil || gen != g || !reflect.DeepEqual(s, status) {
			t.Fatal("owned state lost in recovery")
		}
		actual, _ := readInventory(filepath.Join(filepath.Dir(fresh), inventoryName))
		if !bytes.Equal(image, actual) {
			t.Fatal("ID/owner/token/image changed on restore")
		}
		clear(nk)
	}
	clean, g, err := RunStagingDNS(path, key, id, revision, g, 0, "cleanup", func() bool { return true }, func(permit func() bool, _ []byte, _ dnsrecord.Scope, saved dnsrecord.State, cleanup, readOnly bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		if !permit() || !cleanup || readOnly || saved.State != "created" {
			t.Fatal("cleanup direction")
		}
		image, _ := readInventory(store)
		pending, _, err := inventorystore.ReadStagingDNSPlan(key, id, image)
		if err != nil || pending.Records[0].State != "deleting" || pending.Records[0].CleanupAttempts != 1 {
			t.Fatal("DELETE before durable intent")
		}
		if err := checkpoint(dnsrecord.State{State: "deleting", ID: saved.ID}); err != nil {
			t.Fatal(err)
		}
		return dnsrecord.State{State: "deleted"}, nil
	})
	if err != nil || g != 13 || clean.Records[0].State != "deleted" {
		t.Fatal("cleanup commit failed", err)
	}
}

func TestLinuxDNSOperationRevocationAndUnknownReturnNoAuthority(t *testing.T) {
	for _, point := range []string{"provider-error", "after-network", "after-commit"} {
		t.Run(point, func(t *testing.T) {
			path, _, _, key, id, revision := dnsPlanStoreFixture(t)
			defer clear(key)
			store := filepath.Join(filepath.Dir(path), inventoryName)
			allowed := true
			permit := func() bool {
				if point == "after-commit" {
					image, _ := readInventory(store)
					s, _, err := inventorystore.ReadStagingDNSPlan(key, id, image)
					if err == nil && len(s.Records) > 0 && s.Records[0].State == "created" {
						return false
					}
				}
				return allowed
			}
			s, g, err := RunStagingDNS(path, key, id, revision, 8, 0, "add", permit, func(permit func() bool, _ []byte, _ dnsrecord.Scope, _ dnsrecord.State, _, _ bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
				if !permit() {
					t.Fatal("pre-network permission")
				}
				if err := checkpoint(dnsrecord.State{State: "creating"}); err != nil {
					t.Fatal(err)
				}
				if point == "provider-error" {
					return dnsrecord.State{}, errors.New("provider-secret-sentinel")
				}
				if point == "after-network" {
					allowed = false
				}
				return dnsrecord.State{State: "created", ID: strings.Repeat("c", 32)}, nil
			})
			if point == "provider-error" {
				if err != nil || g != 11 || s.Records[0].State != "creating" {
					t.Fatal("provider error not retained as uncertainty", err)
				}
			} else if err == nil || s.Prepared || g != 0 {
				t.Fatal("revoked transaction published output")
			}
			if point == "after-commit" && !errors.Is(err, ErrInventoryUncertain) {
				t.Fatal("post-commit revocation not uncertain", err)
			}
			stored, gen, err := ReadStagingDNSPlan(path, key, id, revision)
			if err != nil || !stored.Prepared || gen < 10 {
				t.Fatal("intent lost")
			}
			if point != "after-commit" {
				if _, _, err := RunStagingDNS(path, key, id, revision, gen, 0, "check", func() bool { return true }, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
					t.Fatal("early reconciliation bypassed persisted wait")
					return dnsrecord.State{}, nil
				}); err == nil {
					t.Fatal("early retry allowed")
				}
			}
		})
	}
}

func TestLinuxDNSCleanupIntentSnapshotPreservesNoReplay(t *testing.T) {
	path, password, code, key, id, revision := dnsPlanStoreFixture(t)
	defer clear(key)
	_, gen, err := RunStagingDNS(path, key, id, revision, 8, 0, "add", func() bool { return true }, func(_ func() bool, _ []byte, _ dnsrecord.Scope, _ dnsrecord.State, _, _ bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		if err := checkpoint(dnsrecord.State{State: "creating"}); err != nil {
			return dnsrecord.State{}, err
		}
		return dnsrecord.State{State: "created", ID: strings.Repeat("c", 32)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s, gen, err := RunStagingDNS(path, key, id, revision, gen, 0, "cleanup", func() bool { return true }, func(_ func() bool, _ []byte, _ dnsrecord.Scope, saved dnsrecord.State, _, _ bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		if err := checkpoint(dnsrecord.State{State: "deleting", ID: saved.ID}); err != nil {
			return dnsrecord.State{}, err
		}
		return dnsrecord.State{}, errors.New("lost delete response")
	})
	if err != nil || s.Records[0].State != "deleting" {
		t.Fatal("delete intent lost", err)
	}
	backup := filepath.Join(privateSnapshotDir(t), "dns-deleting.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); err != nil {
		t.Fatal(err)
	}
	nk, ni, err := OpenWithIdentity(fresh, password)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(nk)
	rev, _ := Revision(fresh)
	got, g, err := ReadStagingDNSPlan(fresh, nk, ni, rev)
	if err != nil || g != gen || !reflect.DeepEqual(got, s) {
		t.Fatal("cleanup budget/identity changed on restore")
	}
	if _, _, err := RunStagingDNS(fresh, nk, ni, rev, g, 0, "cleanup", func() bool { return true }, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
		t.Fatal("restored deletion repeated DELETE")
		return dnsrecord.State{}, nil
	}); err == nil {
		t.Fatal("restored delete replay accepted")
	}
	original, _ := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
	restored, _ := readInventory(filepath.Join(filepath.Dir(fresh), inventoryName))
	if !bytes.Equal(original, restored) {
		t.Fatal("restored cleanup image changed")
	}
}
