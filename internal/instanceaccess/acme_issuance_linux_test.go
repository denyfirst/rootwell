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

func readyIssuanceStore(t *testing.T) (string, string, string, []byte, []byte, [32]byte) {
	t.Helper()
	path, password, code, key, id, revision := readyOrderStore(t)
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
	if _, _, err := PrepareStagingCertificateRequest(path, key, id, revision, 10, allow); err != nil {
		t.Fatal(err)
	}
	return path, password, code, key, id, revision
}

func TestLinuxIssuanceIntentCommitBeforeCallbackNoReplayAndFullRecovery(t *testing.T) {
	path, password, code, key, id, revision := readyIssuanceStore(t)
	defer clear(key)
	store := filepath.Join(filepath.Dir(path), inventoryName)
	before, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	allow := func() bool { return true }
	calls := 0
	refused := func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (string, error) {
		calls++
		t.Error("refused scope reached callback")
		return "processing", nil
	}
	for _, tc := range []struct {
		rev     [32]byte
		gen     uint64
		refresh bool
		permit  func() bool
	}{{revision, 10, false, allow}, {[32]byte{}, 11, false, allow}, {revision, 11, false, nil}, {revision, 11, false, func() bool { return false }}, {revision, 11, true, allow}} {
		if s, g, err := RunStagingIssuance(path, key, id, tc.rev, tc.gen, tc.refresh, tc.permit, refused); err == nil || s.State != "" || g != 0 {
			t.Fatal("refusal returned issuance")
		}
		after, err := readInventory(store)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("preflight refusal wrote image")
		}
	}
	if err := withAccessWriteLock(path, func() error {
		if _, _, err := RunStagingIssuance(path, key, id, revision, 11, false, allow, refused); err == nil {
			t.Fatal("concurrent writer entered issuance")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var originalPrivate, originalCSR []byte
	defer func() { clear(originalPrivate) }()
	var accountPublic crypto.PublicKey
	s, g, err := RunStagingIssuance(path, key, id, revision, 11, false, allow, func(signer crypto.Signer, account, order, expires string, names []string, private, csr []byte, refresh bool) (string, error) {
		calls++
		image, err := readInventory(store)
		if err != nil {
			t.Fatal(err)
		}
		status, gen, err := inventorystore.ReadStagingIssuance(key, id, image)
		if err != nil || gen != 12 || status.State != "issuance-pending" || refresh || account != durableAccount || order != durableOrder || expires == "" || !reflect.DeepEqual(names, []string{"example.com"}) || len(private) == 0 || len(csr) == 0 {
			t.Fatal("callback before durable exact intent")
		}
		originalPrivate, originalCSR = bytes.Clone(private), bytes.Clone(csr)
		accountPublic = signer.Public()
		return "", errors.New("private callback error sentinel")
	})
	if err != inventorystore.ErrIssuanceUncertain || s.State != "" || g != 0 || calls != 1 {
		t.Fatal("unknown finalize outcome returned success/raw error")
	}
	durable, err := readInventory(store)
	if err != nil {
		t.Fatal(err)
	}
	if s, g, err := RunStagingIssuance(path, key, id, revision, 12, false, allow, refused); err == nil || s.State != "" || g != 0 || calls != 1 {
		t.Fatal("reopened unknown outcome replayed finalize")
	}
	backup := filepath.Join(privateSnapshotDir(t), "issuance.rwfull")
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
		const recovered = "a long test-only issuance recovered password"
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
		freshStore := filepath.Join(filepath.Dir(fresh), inventoryName)
		image, err := readInventory(freshStore)
		if err != nil || !bytes.Equal(image, durable) {
			t.Fatal("full recovery changed exact encrypted intent/request")
		}
		if _, _, err := RunStagingIssuance(fresh, rk, ri, rev, 12, false, allow, refused); err == nil || calls != 1 {
			t.Fatal("restore reconstructed first-attempt authority")
		}
		status, gen, err := RunStagingIssuance(fresh, rk, ri, rev, 12, true, allow, func(signer crypto.Signer, account, order, _ string, names []string, private, csr []byte, refresh bool) (string, error) {
			if !refresh || account != durableAccount || order != durableOrder || !reflect.DeepEqual(names, []string{"example.com"}) || !reflect.DeepEqual(signer.Public(), accountPublic) || !bytes.Equal(private, originalPrivate) || !bytes.Equal(csr, originalCSR) {
				t.Fatal("restored read scope/key/CSR changed")
			}
			return "processing", nil
		})
		clear(rk)
		if err != nil || gen != 13 || status.State != "awaiting-certificate" {
			t.Fatal("restored read-only observation refused")
		}
		if st, err := os.Stat(freshStore); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatal("unsafe restored secret permissions")
		}
	}
	permitted := true
	status, gen, err := RunStagingIssuance(path, key, id, revision, 12, true, func() bool { return permitted }, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (string, error) {
		permitted = false
		return "processing", nil
	})
	if err == nil || status.State != "" || gen != 0 {
		t.Fatal("revoked observation published")
	}
	after, err := readInventory(store)
	if err != nil || !bytes.Equal(after, durable) {
		t.Fatal("read-only failure rewrote durable intent")
	}
	// Incorrect claimed success is not accepted by this non-issued boundary.
	if s, g, err := RunStagingIssuance(path, key, id, revision, 12, true, allow, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (string, error) {
		return "certificate-received", nil
	}); err == nil || s.State != "" || g != 0 {
		t.Fatal("receipt string became saved pair")
	}
	if st, err := os.Stat(store); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal("unsafe intent permissions")
	}
}

func TestLinuxIssuanceFirstObservationAndRefusal(t *testing.T) {
	for _, observation := range []string{"processing", "ready"} {
		t.Run(observation, func(t *testing.T) {
			path, _, _, key, id, revision := readyIssuanceStore(t)
			defer clear(key)
			allow := func() bool { return true }
			calls := 0
			status, gen, err := RunStagingIssuance(path, key, id, revision, 11, false, allow, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (string, error) {
				calls++
				return observation, nil
			})
			if calls != 1 {
				t.Fatal("first attempt did not use exactly one callback")
			}
			if observation == "processing" {
				if err != nil || gen != 13 || status.State != "awaiting-certificate" || status.Observation != observation {
					t.Fatal("first checked processing result refused")
				}
			} else if err != inventorystore.ErrIssuanceUncertain || gen != 0 || status.State != "" {
				t.Fatal("first unconfirmed result returned observation authority")
			}
			saved, current, err := ReadStagingIssuance(path, key, id, revision)
			if err != nil || (observation == "processing" && (current != 13 || saved != status)) || (observation != "processing" && (current != 12 || saved.State != "issuance-pending" || saved.CheckedAt != "")) {
				t.Fatal("saved state lost uncertainty or checked observation")
			}
			if _, _, err := RunStagingIssuance(path, key, id, revision, current, false, allow, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (string, error) {
				calls++
				return "processing", nil
			}); err == nil || calls != 1 {
				t.Fatal("first result enabled a second first attempt")
			}
		})
	}
}

func TestLinuxIssuanceRevocationAfterIntentRetainsUncertainty(t *testing.T) {
	path, _, _, key, id, revision := readyIssuanceStore(t)
	defer clear(key)
	n := 0
	permit := func() bool { n++; return n <= 2 }
	called := false
	if s, g, err := RunStagingIssuance(path, key, id, revision, 11, false, permit, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (string, error) {
		called = true
		return "processing", nil
	}); err == nil || s.State != "" || g != 0 || called {
		t.Fatal("revoked durable operation reached callback")
	}
	s, g, err := ReadStagingIssuance(path, key, id, revision)
	if err != nil || s.State != "issuance-pending" || g != 12 {
		t.Fatal("revocation lost committed uncertainty")
	}
}
