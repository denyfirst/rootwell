//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

const durableOrder = acmeorder.Origin + "/acme/order/1234/5678"

func readyOrderStore(t *testing.T) (string, string, string, []byte, []byte, [32]byte) {
	t.Helper()
	path, password, code, key, id, _ := inventoryFixture(t)
	revision, _ := Revision(path)
	if _, _, err := PrepareStagingAccount(path, key, id, revision, 1, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RunStagingRegistration(path, key, id, revision, 2, durableTerms, false, func() bool { return true }, func(crypto.Signer, string) (string, bool, error) { return durableAccount, false, nil }); err != nil {
		t.Fatal(err)
	}
	return path, password, code, key, id, revision
}
func durableDNS() acmeorder.Instructions {
	return acmeorder.Instructions{URL: durableOrder, Expires: time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05Z"), Records: []acmeorder.TXT{{Domain: "example.com", Name: "_acme-challenge.example.com", Value: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Required: true}}}
}

func TestLinuxManualDNSDurableCheckpointSameOrderRestoreAndLocalAcknowledgement(t *testing.T) {
	path, password, code, key, id, revision := readyOrderStore(t)
	defer clear(key)
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, _ := readInventory(store)
	refused := func(crypto.Signer, string, string, []string, func(string) error) (acmeorder.Instructions, error) {
		t.Error("refused writer reached network")
		return acmeorder.Instructions{}, nil
	}
	for _, tc := range []struct {
		revision [32]byte
		gen      uint64
		permit   func() bool
	}{{revision, 3, func() bool { return true }}, {[32]byte{}, 4, func() bool { return true }}, {revision, 4, nil}, {revision, 4, func() bool { return false }}} {
		if _, _, err := RunStagingOrder(path, key, id, tc.revision, tc.gen, []string{"example.com"}, false, tc.permit, refused); err == nil {
			t.Fatal("invalid scope authorized")
		}
		after, _ := readInventory(store)
		if !bytes.Equal(before, after) {
			t.Fatal("refused scope changed image")
		}
	}
	if err := withAccessWriteLock(path, func() error {
		_, _, err := RunStagingOrder(path, key, id, revision, 4, []string{"example.com"}, false, func() bool { return true }, refused)
		if !errors.Is(err, ErrAccessBusy) {
			t.Fatal("second writer entered")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var public crypto.PublicKey
	_, _, err := RunStagingOrder(path, key, id, revision, 4, []string{"example.com"}, false, func() bool { return true }, func(signer crypto.Signer, account, order string, names []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		public = signer.Public()
		if account != durableAccount || order != "" || !reflect.DeepEqual(names, []string{"example.com"}) {
			t.Fatal("wrong request scope")
		}
		image, _ := readInventory(store)
		status, gen, err := inventorystore.ReadStagingOrder(key, id, image)
		if err != nil || gen != 5 || status.State != "request-pending" {
			t.Fatal("network preceded durable intent")
		}
		if err := checkpoint(durableOrder); err != nil {
			t.Fatal(err)
		}
		image, _ = readInventory(store)
		status, gen, err = inventorystore.ReadStagingOrder(key, id, image)
		if err != nil || gen != 6 || status.State != "order-known" {
			t.Fatal("checkpoint not durable before body")
		}
		if checkpoint(durableOrder) == nil {
			t.Fatal("checkpoint replay accepted")
		}
		return acmeorder.Instructions{}, errors.New("synthetic body loss")
	})
	if err == nil {
		t.Fatal("body loss reported success")
	}
	status, gen, err := ReadStagingOrder(path, key, id, revision)
	if err != nil || gen != 6 || status.State != "order-known" {
		t.Fatal("known order lost")
	}
	if _, _, err := RunStagingOrder(path, key, id, revision, 6, []string{"example.com"}, false, func() bool { return true }, refused); err == nil {
		t.Fatal("known order recreated")
	}
	backup := filepath.Join(privateSnapshotDir(t), "order.rwfull")
	if err := ExportFullSnapshot(path, backup, password, code); err != nil {
		t.Fatal(err)
	}
	for _, method := range []SnapshotUnlock{SnapshotPassword, SnapshotRecoveryCode} {
		fresh := filepath.Join(privateSnapshotDir(t), "access.json")
		credential := password
		if method == SnapshotRecoveryCode {
			credential = code
		}
		if err := RestoreFullSnapshot(backup, fresh, credential, method); err != nil {
			t.Fatal(err)
		}
		const recovered = "a long recovered test-only DNS request password"
		if _, err := RecoverPassword(fresh, code, recovered); err != nil {
			t.Fatal(err)
		}
		rk, ri, err := OpenWithIdentity(fresh, recovered)
		if err != nil {
			t.Fatal(err)
		}
		rev, _ := Revision(fresh)
		status, gen, err := RunStagingOrder(fresh, rk, ri, rev, 6, nil, true, func() bool { return true }, func(signer crypto.Signer, account, order string, names []string, _ func(string) error) (acmeorder.Instructions, error) {
			if !reflect.DeepEqual(signer.Public(), public) || account != durableAccount || order != durableOrder || !reflect.DeepEqual(names, []string{"example.com"}) {
				t.Fatal("restore/recovery changed account/order scope")
			}
			return durableDNS(), nil
		})
		if err != nil || gen != 7 || status.State != "dns-ready" {
			t.Fatal("restored order did not resume")
		}
		status, gen, err = AcknowledgeStagingDNS(fresh, rk, ri, rev, 7, func() bool { return true })
		if err != nil || gen != 8 || status.State != "dns-acknowledged" {
			t.Fatal("local acknowledgement refused")
		}
		if _, _, err := AcknowledgeStagingDNS(fresh, rk, ri, rev, 7, func() bool { return true }); !errors.Is(err, inventorystore.ErrStaleGeneration) {
			t.Fatal("stale acknowledgement accepted")
		}
		if info, err := os.Lstat(filepath.Join(filepath.Dir(fresh), inventoryName)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("restored order permissions unsafe")
		}
		clear(rk)
	}
}

func TestLinuxManualDNSMissingURICannotResumeOrRecreate(t *testing.T) {
	path, _, _, key, id, revision := readyOrderStore(t)
	defer clear(key)
	calls := 0
	_, _, err := RunStagingOrder(path, key, id, revision, 4, []string{"example.com"}, false, func() bool { return true }, func(crypto.Signer, string, string, []string, func(string) error) (acmeorder.Instructions, error) {
		calls++
		return acmeorder.Instructions{}, errors.New("response lost before Location")
	})
	if err == nil {
		t.Fatal("lost creation reported success")
	}
	status, gen, err := ReadStagingOrder(path, key, id, revision)
	if err != nil || gen != 5 || status.State != "request-pending" {
		t.Fatal("uncertainty not durable")
	}
	for _, resume := range []bool{false, true} {
		if _, _, err := RunStagingOrder(path, key, id, revision, 5, nil, resume, func() bool { return true }, func(crypto.Signer, string, string, []string, func(string) error) (acmeorder.Instructions, error) {
			calls++
			return durableDNS(), nil
		}); err == nil || calls != 1 {
			t.Fatal("unlocated order acquired new authority")
		}
	}
}

func TestLinuxManualDNSCancelledAfterCheckpointKeepsKnownOrder(t *testing.T) {
	path, _, _, key, id, revision := readyOrderStore(t)
	defer clear(key)
	permitted := true
	_, _, err := RunStagingOrder(path, key, id, revision, 4, []string{"example.com"}, false, func() bool { return permitted }, func(_ crypto.Signer, _, _ string, _ []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		if err := checkpoint(durableOrder); err != nil {
			t.Fatal(err)
		}
		permitted = false
		return durableDNS(), nil
	})
	if err == nil {
		t.Fatal("cancelled result published")
	}
	status, gen, err := ReadStagingOrder(path, key, id, revision)
	if err != nil || gen != 6 || status.State != "order-known" {
		t.Fatal("cancelled checkpoint lost")
	}
}
