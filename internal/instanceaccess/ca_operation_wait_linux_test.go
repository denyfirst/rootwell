//go:build linux

package instanceaccess

import (
	"crypto"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

func TestLinuxCAFailureWaitDurableAndFullRecovery(t *testing.T) {
	path, password, code, key, id, rev := readyOrderStore(t)
	defer clear(key)
	wait := time.Now().UTC().Add(time.Hour)
	calls := 0
	_, _, err := RunStagingOrder(path, key, id, rev, 4, []string{"example.com"}, false, func() bool { return true }, func(crypto.Signer, string, string, []string, func(string) error) (acmeorder.Instructions, error) {
		calls++
		return acmeorder.Instructions{}, &providerretry.Failure{Hint: providerretry.Hint{NotBefore: wait}}
	})
	if err == nil || calls != 1 {
		t.Fatal("failed CA call claimed success or retried")
	}
	image, err := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
	if err != nil {
		t.Fatal(err)
	}
	status, g, err := inventorystore.ReadStagingProviderWait(key, id, image)
	if err != nil || status.Ready || status.Blocked || status.NotBefore != wait.Format(time.RFC3339Nano) || g != 6 {
		t.Fatal("failure wait not durable", err)
	}
	order, og, err := ReadStagingOrder(path, key, id, rev)
	if err != nil || og != g || order.State != "request-pending" {
		t.Fatal("error wait changed pending order", err)
	}
	if err := RunStagingProviderRead(path, key, id, rev, func() bool { return true }, func(func() bool) error { t.Fatal("global CA wait bypassed by another read"); return nil }); !errors.Is(err, inventorystore.ErrTimingWait) {
		t.Fatal("global wait not enforced", err)
	}
	backup := filepath.Join(privateSnapshotDir(t), "ca-wait.rwfull")
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
	r, err := Revision(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := RunStagingProviderRead(fresh, k, install, r, func() bool { return true }, func(func() bool) error { t.Fatal("restore forgot CA wait"); return nil }); !errors.Is(err, inventorystore.ErrTimingWait) {
		t.Fatal("restored provider wait missing", err)
	}
}

func TestLinuxCAOrderSuccessPublishesWaitInSameResult(t *testing.T) {
	path, _, _, key, id, rev := readyOrderStore(t)
	defer clear(key)
	wait := time.Now().UTC().Add(time.Hour)
	_, g, err := RunStagingOrder(path, key, id, rev, 4, []string{"example.com"}, false, func() bool { return true }, func(_ crypto.Signer, _, _ string, _ []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		if err := checkpoint(durableOrder); err != nil {
			return acmeorder.Instructions{}, err
		}
		info := durableDNS()
		info.Wait = providerretry.Hint{NotBefore: wait}
		return info, nil
	})
	if err != nil || g != 7 {
		t.Fatal("success wait added a separate generation or refused result", err)
	}
	image, _ := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
	status, wg, err := inventorystore.ReadStagingProviderWait(key, id, image)
	if err != nil || wg != g || status.Ready || status.NotBefore != wait.Format(time.RFC3339Nano) {
		t.Fatal("success result lost wait", err)
	}
}

func TestLinuxCACertificateWaitSurvivesRedactionAndKeepsLeaseDirection(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "processing", true: "failure"}[failed], func(t *testing.T) {
			path, _, _, key, id, rev := readyIssuanceStore(t)
			defer clear(key)
			wait := time.Now().UTC().Add(time.Hour)
			calls := 0
			s, g, err := RunStagingCertificate(path, key, id, rev, 11, false, func() bool { return true }, func(_ crypto.Signer, _, _, expires string, _ []string, _, _ []byte, readOnly bool) (acmestaging.CertificateObservation, error) {
				calls++
				if readOnly {
					t.Fatal("first lease lost direction")
				}
				if failed {
					return acmestaging.CertificateObservation{}, &providerretry.Failure{Hint: providerretry.Hint{NotBefore: wait}}
				}
				return acmestaging.CertificateObservation{State: "processing", Expires: expires, Wait: providerretry.Hint{NotBefore: wait}}, nil
			})
			if calls != 1 || failed && (!errors.Is(err, inventorystore.ErrIssuanceUncertain) || s.State != "" || g != 0) || !failed && (err != nil || g != 13 || s.State != "awaiting-certificate") {
				t.Fatal("certificate wait changed error/result contract", err)
			}
			image, _ := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
			status, wg, err := inventorystore.ReadStagingProviderWait(key, id, image)
			if err != nil || status.Ready || status.NotBefore != wait.Format(time.RFC3339Nano) || wg != 13 {
				t.Fatal("certificate wait lost at redaction/result boundary", err)
			}
			if _, _, err := RunStagingCertificate(path, key, id, rev, wg, false, func() bool { return true }, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (acmestaging.CertificateObservation, error) {
				t.Fatal("wait or consumed finalize lease bypassed")
				return acmestaging.CertificateObservation{}, nil
			}); err == nil {
				t.Fatal("finalize replay admitted")
			}
		})
	}
}

func TestLinuxCAValidationWaitKeepsPendingOrCheckedScope(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "checked", true: "failure"}[failed], func(t *testing.T) {
			path, _, _, key, id, rev := readyOrderStore(t)
			defer clear(key)
			permit := func() bool { return true }
			if _, _, err := RunStagingOrder(path, key, id, rev, 4, []string{"example.com"}, false, permit, func(_ crypto.Signer, _, _ string, _ []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
				if err := checkpoint(durableOrder); err != nil {
					return acmeorder.Instructions{}, err
				}
				return durableDNS(), nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := AcknowledgeStagingDNS(path, key, id, rev, 7, permit); err != nil {
				t.Fatal(err)
			}
			wait := time.Now().UTC().Add(time.Hour)
			_, _, callErr := RunStagingValidation(path, key, id, rev, 8, false, permit, func(_ crypto.Signer, _ string, saved acmeorder.Instructions, _ []string, refresh bool) (acmeorder.Validation, error) {
				if refresh {
					t.Fatal("initial validation lost direction")
				}
				if failed {
					return acmeorder.Validation{}, &providerretry.Failure{Hint: providerretry.Hint{NotBefore: wait}}
				}
				return acmeorder.Validation{URL: saved.URL, Expires: saved.Expires, OrderStatus: "ready", Statuses: []string{"valid"}, Wait: providerretry.Hint{NotBefore: wait}}, nil
			})
			if failed != (callErr != nil) {
				t.Fatal("validation error contract changed")
			}
			image, _ := readInventory(filepath.Join(filepath.Dir(path), inventoryName))
			status, g, err := inventorystore.ReadStagingProviderWait(key, id, image)
			if err != nil || g != 10 || status.Ready || status.NotBefore != wait.Format(time.RFC3339Nano) {
				t.Fatal("validation lost wait", err)
			}
			order, _, err := ReadStagingOrder(path, key, id, rev)
			want := "domain-verified"
			if failed {
				want = "validation-pending"
			}
			if err != nil || order.State != want {
				t.Fatal("wait invented validation outcome", err)
			}
		})
	}
}
