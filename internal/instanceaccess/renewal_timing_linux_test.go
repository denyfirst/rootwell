//go:build linux

package instanceaccess

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/providerretry"
	"github.com/denyfirst/rootwell/internal/renewalpolicy"
	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

func TestLinuxRenewalTimingIntentLockSourceAndFullRecovery(t *testing.T) {
	path, code, key, id, fp, revision := completedClosureStore(t)
	defer clear(key)
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	allow := func() bool { return true }
	refused := func(func() bool, []byte) (renewalrecord.Observation, error) {
		t.Fatal("refused scope contacted connector")
		return renewalrecord.Observation{}, nil
	}
	for _, tc := range []struct {
		revision [32]byte
		gen      uint64
		permit   func() bool
	}{{revision, 12, allow}, {[32]byte{}, 13, allow}, {revision, 13, nil}, {revision, 13, func() bool { return false }}} {
		if s, g, err := RunStagingRenewalTiming(path, key, id, tc.revision, tc.gen, fp, tc.permit, refused); err == nil || s.Prepared || g != 0 {
			t.Fatal("invalid timing authority accepted")
		}
		after, err := readInventory(store)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refusal mutated inventory")
		}
	}
	var borrowed []byte
	s, gen, err := RunStagingRenewalTiming(path, key, id, revision, 13, fp, allow, func(permit func() bool, der []byte) (renewalrecord.Observation, error) {
		borrowed = der
		image, err := readInventory(store)
		if err != nil {
			t.Fatal(err)
		}
		intent, g, err := inventorystore.ReadStagingRenewalTiming(key, id, image, 14, fp)
		if err != nil || g != 14 || !intent.Pending || intent.Failures != 1 || !permit() {
			t.Fatal("GET preceded durable intent", err)
		}
		if _, _, err := ReadStagingRenewalTiming(path, key, id, revision, 14, fp); !errors.Is(err, ErrAccessBusy) {
			t.Fatal("lock released during callback", err)
		}
		cid, err := renewalpolicy.CertificateID(der)
		if err != nil {
			t.Fatal("wrong public source", err)
		}
		now := time.Now().UTC()
		return renewalrecord.Observation{CertificateID: cid, Available: true, Information: renewalpolicy.Information{Window: renewalpolicy.Window{Start: now.Add(10 * time.Minute), End: now.Add(15 * time.Minute)}, CheckedAt: now, CheckAfter: now.Add(6 * time.Hour)}}, nil
	})
	if err != nil || gen != 15 || !s.Prepared || s.Pending || s.State != "ari" {
		t.Fatal("timing commit failed", err)
	}
	if len(borrowed) == 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed DER bytes retained")
	}
	if info, err := os.Stat(store); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("unsafe timing image")
	}
	image, _ := readInventory(store)
	backup := filepath.Join(privateSnapshotDir(t), "timing.rwfull")
	if err := ExportFullSnapshot(path, backup, closedGateTestPassword, code); err != nil {
		t.Fatal(err)
	}
	for _, method := range []SnapshotUnlock{SnapshotPassword, SnapshotRecoveryCode} {
		fresh := filepath.Join(privateSnapshotDir(t), "access.json")
		credential := closedGateTestPassword
		if method == SnapshotRecoveryCode {
			credential = code
		}
		if err := RestoreFullSnapshot(backup, fresh, credential, method); err != nil {
			t.Fatal(err)
		}
		const recovered = "a separate long renewal timing recovery password"
		if _, err := RecoverPassword(fresh, code, recovered); err != nil {
			t.Fatal(err)
		}
		rk, ri, err := OpenWithIdentity(fresh, recovered)
		if err != nil {
			t.Fatal(err)
		}
		rrev, err := Revision(fresh)
		if err != nil {
			t.Fatal(err)
		}
		reread, g, err := ReadStagingRenewalTiming(fresh, rk, ri, rrev, gen, fp)
		if err != nil || g != gen || !reflect.DeepEqual(s, reread) {
			t.Fatal("restore rerolled timing", err)
		}
		actual, _ := readInventory(filepath.Join(filepath.Dir(fresh), inventoryName))
		if !bytes.Equal(image, actual) {
			t.Fatal("recovery changed complete image")
		}
		clear(rk)
	}
	if err := os.Chmod(store, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadStagingRenewalTiming(path, key, id, revision, gen, fp); err == nil {
		t.Fatal("unsafe image readable")
	}
	if _, _, err := RunStagingRenewalTiming(path, key, id, revision, gen, fp, allow, refused); err == nil {
		t.Fatal("unsafe image gained I/O")
	}
}

func TestLinuxRenewalTimingRevocationPendingSnapshotAndNoRetryReset(t *testing.T) {
	for _, point := range []string{"after-intent", "after-network", "after-outcome"} {
		t.Run(point, func(t *testing.T) {
			path, code, key, id, fp, revision := completedClosureStore(t)
			defer clear(key)
			store := filepath.Join(filepath.Dir(path), inventoryName)
			allowed, called := true, false
			permit := func() bool {
				image, err := readInventory(store)
				if err != nil {
					return false
				}
				if point == "after-intent" || point == "after-outcome" {
					s, _, err := inventorystore.ReadStagingRenewalTiming(key, id, image, 14, fp)
					if point == "after-intent" && err == nil && s.Pending {
						return false
					}
					if point == "after-outcome" {
						_, g, err := inventorystore.Open(key, id, image)
						if err == nil && g == 15 {
							return false
						}
					}
				}
				return allowed
			}
			s, g, err := RunStagingRenewalTiming(path, key, id, revision, 13, fp, permit, func(func() bool, []byte) (renewalrecord.Observation, error) {
				called = true
				if point == "after-network" {
					allowed = false
				}
				return renewalrecord.Observation{}, &renewalrecord.Failure{Temporary: true, Hint: providerretry.Hint{NotBefore: time.Now().UTC().Add(3 * time.Hour)}}
			})
			if err == nil || s.Prepared || g != 0 || point == "after-intent" && called {
				t.Fatal("revoked operation published metadata")
			}
			if point != "after-network" && !errors.Is(err, ErrInventoryUncertain) {
				t.Fatal("committed but revoked outcome not uncertain", err)
			}
			image, _ := readInventory(store)
			_, generation, err := inventorystore.Open(key, id, image)
			if err != nil {
				t.Fatal(err)
			}
			saved, _, err := ReadStagingRenewalTiming(path, key, id, revision, generation, fp)
			if err != nil || generation < 14 || !saved.Prepared || saved.Failures != 1 {
				t.Fatal("intent/failure lost", err)
			}
			backup := filepath.Join(privateSnapshotDir(t), "interrupted-timing.rwfull")
			if err := ExportFullSnapshot(path, backup, closedGateTestPassword, code); err != nil {
				t.Fatal(err)
			}
			fresh := filepath.Join(privateSnapshotDir(t), "access.json")
			if err := RestoreFullSnapshot(backup, fresh, code, SnapshotRecoveryCode); err != nil {
				t.Fatal(err)
			}
			rk, ri, err := OpenWithIdentity(fresh, closedGateTestPassword)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(rk)
			rrev, _ := Revision(fresh)
			reread, _, err := ReadStagingRenewalTiming(fresh, rk, ri, rrev, generation, fp)
			if err != nil || !reflect.DeepEqual(saved, reread) {
				t.Fatal("interrupted policy changed on recovery", err)
			}
			if saved.Pending {
				retired, _, err := InterruptStagingRenewalTiming(fresh, rk, ri, rrev, generation, fp, func() bool { return true })
				if err != nil || retired.Pending || retired.NextCheck != saved.NextCheck || retired.FallbackAt != saved.FallbackAt || retired.Failures != saved.Failures {
					t.Fatal("retirement erased wait/choice", err)
				}
			} else if saved.ProviderNotBefore == "" || saved.CanRead {
				t.Fatal("committed provider wait lost")
			}
		})
	}
}
