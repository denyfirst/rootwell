//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/denyfirst/rootwell/internal/acmeorder"
)

func TestLinuxCertificateRequestCustodyPermissionAtomicityAndFullRecovery(t *testing.T) {
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
	if _, _, err := RunStagingValidation(path, key, id, revision, 8, false, allow, func(_ crypto.Signer, _ string, saved acmeorder.Instructions, _ []string, _ bool) (acmeorder.Validation, error) {
		return acmeorder.Validation{URL: saved.URL, Expires: saved.Expires, OrderStatus: "ready", Statuses: []string{"valid"}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	late := func() bool { n++; return n == 1 }
	for _, tc := range []struct {
		rev    [32]byte
		gen    uint64
		permit func() bool
	}{
		{revision, 9, allow}, {[32]byte{}, 10, allow}, {revision, 10, nil}, {revision, 10, func() bool { return false }}, {revision, 10, late},
	} {
		if s, gen, err := PrepareStagingCertificateRequest(path, key, id, tc.rev, tc.gen, tc.permit); err == nil || s.Prepared || gen != 0 {
			t.Fatal("refusal published or wrote a key")
		}
		after, err := readInventory(store)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refusal changed complete image")
		}
	}
	if err := withAccessWriteLock(path, func() error {
		if s, gen, err := PrepareStagingCertificateRequest(path, key, id, revision, 10, allow); err == nil || s.Prepared || gen != 0 {
			t.Fatal("concurrent writer acquired custody")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	prepared, gen, err := PrepareStagingCertificateRequest(path, key, id, revision, 10, allow)
	if err != nil || !prepared.Prepared || gen != 11 {
		t.Fatal("valid key preparation refused")
	}
	durable, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	if s, gen, err := PrepareStagingCertificateRequest(path, key, id, revision, 11, allow); err == nil || s.Prepared || gen != 0 {
		t.Fatal("existing certificate key replaced")
	}
	after, err := readInventory(store)
	if err != nil || !bytes.Equal(durable, after) {
		t.Fatal("repeat replaced durable key/CSR")
	}
	backup := filepath.Join(privateSnapshotDir(t), "certificate-request.rwfull")
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
		const recovered = "a long test-only certificate request recovered password"
		if _, err := RecoverPassword(fresh, code, recovered); err != nil {
			t.Fatal(err)
		}
		rk, ri, err := OpenWithIdentity(fresh, recovered)
		if err != nil {
			t.Fatal(err)
		}
		rev, err := Revision(fresh)
		if err != nil {
			t.Fatal(err)
		}
		order, restored, g, err := ReadStagingOrderPreparation(fresh, rk, ri, rev)
		clear(rk)
		if err != nil || order.State != "domain-verified" || restored != prepared || g != 11 {
			t.Fatal("recovery changed request identity")
		}
		freshStore := filepath.Join(filepath.Dir(fresh), inventoryName)
		restoredImage, err := readInventory(freshStore)
		if err != nil || !bytes.Equal(durable, restoredImage) {
			t.Fatal("recovery changed exact encrypted key/CSR/order/account")
		}
		if info, err := os.Stat(freshStore); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("unsafe restored secret permissions")
		}
	}
}
