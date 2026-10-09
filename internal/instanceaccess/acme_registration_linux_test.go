//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto"
	"errors"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

const durableTerms = "https://letsencrypt.org/documents/terms.pdf"
const durableAccount = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/1234"

func TestLinuxRegistrationPendingSameKeyRestoreRecoveryAndRefusals(t *testing.T) {
	path, password, code, key, id, _ := inventoryFixture(t)
	defer clear(key)
	revision, _ := Revision(path)
	original, _, err := PrepareStagingAccount(path, key, id, revision, 1, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, _ := readInventory(store)
	use := func(crypto.Signer, string) (string, bool, error) {
		t.Error("refused transaction reached signer callback")
		return "", false, nil
	}
	for _, tc := range []struct {
		revision [32]byte
		expected uint64
		permit   func() bool
	}{{revision, 1, func() bool { return true }}, {[32]byte{}, 2, func() bool { return true }}, {revision, 2, nil}, {revision, 2, func() bool { return false }}} {
		if _, _, err := RunStagingRegistration(path, key, id, tc.revision, tc.expected, durableTerms, false, tc.permit, use); err == nil {
			t.Fatal("invalid transaction authorized")
		}
		after, _ := readInventory(store)
		if !bytes.Equal(before, after) {
			t.Fatal("refused transaction changed image")
		}
	}
	if err := withAccessWriteLock(path, func() error {
		_, _, err := RunStagingRegistration(path, key, id, revision, 2, durableTerms, false, func() bool { return true }, use)
		if !errors.Is(err, ErrAccessBusy) {
			t.Fatal("concurrent writer entered account")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err = RunStagingRegistration(path, key, id, revision, 2, durableTerms, false, func() bool { return true }, func(signer crypto.Signer, terms string) (string, bool, error) {
		if signer == nil || terms != durableTerms {
			t.Fatal("intent signer missing")
		}
		return "", false, errors.New("simulated connection loss")
	})
	if err == nil {
		t.Fatal("uncertain operation reported success")
	}
	pending, gen, err := ReadStagingAccount(path, key, id, revision)
	if err != nil || gen != 3 || pending.Registration != "registration-pending" || pending.Fingerprint != original.Fingerprint {
		t.Fatal("pending account not durable")
	}
	backup := filepath.Join(privateSnapshotDir(t), "pending.rwfull")
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
		const recovered = "a long recovered test-only account password"
		if _, err := RecoverPassword(fresh, code, recovered); err != nil {
			t.Fatal(err)
		}
		newKey, newID, err := OpenWithIdentity(fresh, recovered)
		if err != nil {
			t.Fatal(err)
		}
		newRevision, _ := Revision(fresh)
		ready, gen, err := RunStagingRegistration(fresh, newKey, newID, newRevision, 3, "", true, func() bool { return true }, func(signer crypto.Signer, terms string) (string, bool, error) {
			if signer == nil || terms != durableTerms {
				t.Fatal("restored intent changed")
			}
			return durableAccount, false, nil
		})
		clear(newKey)
		if err != nil || gen != 4 || ready.Registration != "registered" || ready.Fingerprint != original.Fingerprint {
			t.Fatal("restored/recovered same key did not reconcile")
		}
	}
	absent, gen, err := RunStagingRegistration(path, key, id, revision, 3, "", true, func() bool { return true }, func(crypto.Signer, string) (string, bool, error) { return "", true, nil })
	if err != nil || gen != 4 || absent.Registration != "not-registered" || absent.Fingerprint != original.Fingerprint {
		t.Fatal("confirmed absence replaced key")
	}
}

func TestLinuxRegistrationPostRenameUncertaintyKeepsReconciliationIntent(t *testing.T) {
	path, _, _, key, id, _ := inventoryFixture(t)
	defer clear(key)
	revision, _ := Revision(path)
	original, _, err := PrepareStagingAccount(path, key, id, revision, 1, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, _ := readInventory(store)
	pending, _, _, err := inventorystore.BeginStagingRegistration(key, id, before, 2, durableTerms)
	if err != nil {
		t.Fatal(err)
	}
	err = replaceInventoryWithHooks(store, pending, func(f *os.File, _ []byte) error { _, _ = f.Write([]byte("partial")); return syscall.ENOSPC }, syncAccessDirectory)
	if err == nil {
		t.Fatal("disk-full intent write succeeded")
	}
	after, _ := readInventory(store)
	if !bytes.Equal(before, after) {
		t.Fatal("pre-rename intent fault changed store")
	}
	err = replaceInventoryWithSync(store, pending, func(string) error { return errors.New("synthetic fsync fault") })
	if !errors.Is(err, ErrInventoryUncertain) {
		t.Fatal("post-rename intent loss not uncertain")
	}
	status, gen, err := ReadStagingAccount(path, key, id, revision)
	if err != nil || gen != 3 || status.Registration != "registration-pending" {
		t.Fatal("uncertain intent unavailable")
	}
	ready, gen, err := RunStagingRegistration(path, key, id, revision, 3, "", true, func() bool { return true }, func(crypto.Signer, string) (string, bool, error) { return durableAccount, false, nil })
	if err != nil || gen != 4 || ready.Fingerprint != original.Fingerprint || ready.Registration != "registered" {
		t.Fatal("uncertain intent could not reconcile same key")
	}
}
