//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func TestLinuxDNSValidationDurableUncertaintyNoReplayRestoreAndRevocation(t *testing.T) {
	path, password, code, key, id, revision := readyOrderStore(t)
	defer clear(key)
	allow := func() bool { return true }
	if _, _, err := RunStagingOrder(path, key, id, revision, 4, []string{"example.com"}, false, allow, func(_ crypto.Signer, _, _ string, _ []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		if err := checkpoint(durableOrder); err != nil {
			return acmeorder.Instructions{}, err
		}
		return durableDNS(), nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AcknowledgeStagingDNS(path, key, id, revision, 7, allow); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, _ := readInventory(store)
	calls := 0
	refused := func(crypto.Signer, string, acmeorder.Instructions, []string, bool) (acmeorder.Validation, error) {
		calls++
		t.Error("refused authority reached callback")
		return acmeorder.Validation{}, nil
	}
	for _, tc := range []struct {
		rev     [32]byte
		gen     uint64
		permit  func() bool
		refresh bool
	}{{revision, 7, allow, false}, {[32]byte{}, 8, allow, false}, {revision, 8, nil, false}, {revision, 8, func() bool { return false }, false}, {revision, 8, allow, true}} {
		if _, _, err := RunStagingValidation(path, key, id, tc.rev, tc.gen, tc.refresh, tc.permit, refused); err == nil {
			t.Fatal("invalid scope authorized")
		}
		after, _ := readInventory(store)
		if !bytes.Equal(before, after) {
			t.Fatal("refusal mutated image")
		}
	}
	var public crypto.PublicKey
	if _, _, err := RunStagingValidation(path, key, id, revision, 8, false, allow, func(signer crypto.Signer, account string, saved acmeorder.Instructions, names []string, refresh bool) (acmeorder.Validation, error) {
		calls++
		public = signer.Public()
		image, _ := readInventory(store)
		state, gen, err := inventorystore.ReadStagingOrder(key, id, image)
		if err != nil || state.State != "validation-pending" || gen != 9 || account != durableAccount || saved.URL != durableOrder || len(saved.Records) != 1 || !reflect.DeepEqual(names, []string{"example.com"}) || refresh {
			t.Fatal("I/O before durable exact scope")
		}
		return acmeorder.Validation{}, errors.New("synthetic unknown Accept outcome")
	}); err == nil {
		t.Fatal("uncertainty published success")
	}
	if _, _, err := RunStagingValidation(path, key, id, revision, 9, false, allow, refused); err == nil || calls != 1 {
		t.Fatal("uncertain acceptance replayed")
	}
	backup := filepath.Join(privateSnapshotDir(t), "validation.rwfull")
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
		const recovered = "a long test-only CA validation recovered password"
		if _, err := RecoverPassword(fresh, code, recovered); err != nil {
			t.Fatal(err)
		}
		rk, ri, err := OpenWithIdentity(fresh, recovered)
		if err != nil {
			t.Fatal(err)
		}
		rev, _ := Revision(fresh)
		status, gen, err := RunStagingValidation(fresh, rk, ri, rev, 9, true, allow, func(signer crypto.Signer, account string, saved acmeorder.Instructions, names []string, refresh bool) (acmeorder.Validation, error) {
			if !refresh || !reflect.DeepEqual(signer.Public(), public) || account != durableAccount || saved.URL != durableOrder || !reflect.DeepEqual(names, []string{"example.com"}) {
				t.Fatal("restore changed scope or allowed Accept")
			}
			return acmeorder.Validation{URL: saved.URL, Expires: saved.Expires, OrderStatus: "ready", Statuses: []string{"valid"}}, nil
		})
		if err != nil || gen != 11 || status.State != "domain-verified" {
			t.Fatal("read-only result could not reconcile")
		}
		if st, err := os.Stat(filepath.Join(filepath.Dir(fresh), inventoryName)); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatal("unsafe restored mode")
		}
		clear(rk)
	}
	permitted := true
	if status, gen, err := RunStagingValidation(path, key, id, revision, 9, true, func() bool { return permitted }, func(_ crypto.Signer, _ string, saved acmeorder.Instructions, _ []string, refresh bool) (acmeorder.Validation, error) {
		if !refresh {
			t.Fatal("replay")
		}
		permitted = false
		return acmeorder.Validation{URL: saved.URL, Expires: saved.Expires, OrderStatus: "ready", Statuses: []string{"valid"}}, nil
	}); err == nil || gen != 0 || status.State != "" {
		t.Fatal("revoked result published")
	}
	if status, gen, err := ReadStagingOrder(path, key, id, revision); err != nil || gen != 10 || status.State != "validation-pending" {
		t.Fatal("revoked result lost durable intent")
	}
}
