//go:build linux

package instanceaccess

import (
	"crypto"
	"errors"
	"path/filepath"
	"testing"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func TestLinuxRenewalIntentBeforeIOReadOnlyResumeAndFullRecovery(t *testing.T) {
	path, code, key, id, fp, rev := completedClosureStore(t)
	defer clear(key)
	allow := func() bool { return true }
	source, g, err := ReadStagingRenewalSource(path, key, id, rev, 13, fp)
	if err != nil || g != 13 || source.Fingerprint != fp || len(source.Domains) != 2 {
		t.Fatal("completed renewal selection refused")
	}
	calls := 0
	use := func(_ crypto.Signer, _ string, _ string, _ []string, _ func(string) error) (acmeorder.Instructions, error) {
		calls++
		t.Fatal("refused renewal contacted provider")
		return acmeorder.Instructions{}, nil
	}
	if _, _, err := RunStagingRenewalOrder(path, key, id, rev, 13, fp, allow, use); err == nil || calls != 0 {
		t.Fatal("active source request replaced")
	}
	if _, g, err := CloseStagingRequest(path, key, id, rev, 13, allow); err != nil || g != 14 {
		t.Fatal(err)
	}
	for _, r := range [][32]byte{rev, {}} {
		if _, _, err := RunStagingRenewalOrder(path, key, id, r, 13, fp, allow, use); err == nil || calls != 0 {
			t.Fatal("stale renewal borrowed signer")
		}
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	info := durableDNS()
	wildcard := info.Records[0]
	wildcard.Domain = "*.example.com"
	wildcard.Value = "B" + wildcard.Value[1:]
	info.Records = []acmeorder.TXT{wildcard, info.Records[0]}
	info.URL = acmeorder.Origin + "/acme/order/1234/9999"
	use = func(signer crypto.Signer, account, order string, names []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		calls++
		if signer == nil || order != "" || len(names) != 2 {
			t.Fatal("new renewal borrowed old scope")
		}
		image, err := readInventory(store)
		if err != nil {
			t.Fatal(err)
		}
		status, g, err := inventorystore.ReadStagingOrder(key, id, image)
		if err != nil || g != 15 || status.State != "request-pending" || status.RenewalSource != fp {
			t.Fatal("renewal IO preceded intent")
		}
		if err := checkpoint(info.URL); err != nil {
			return acmeorder.Instructions{}, err
		}
		return acmeorder.Instructions{}, errors.New("synthetic lost response")
	}
	if _, _, err := RunStagingRenewalOrder(path, key, id, rev, 14, fp, allow, use); err == nil || calls != 1 {
		t.Fatal("lost renewal falsely confirmed")
	}
	if _, _, err := RunStagingRenewalOrder(path, key, id, rev, 16, fp, allow, use); err == nil || calls != 1 {
		t.Fatal("lost renewal recreated")
	}
	use = func(signer crypto.Signer, account, order string, names []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
		calls++
		if signer == nil || order != info.URL {
			t.Fatal("renewal resumed another request")
		}
		return info, nil
	}
	status, g, err := RunStagingOrder(path, key, id, rev, 16, nil, true, allow, use)
	if err != nil || g != 17 || status.RenewalSource != fp || calls != 2 {
		t.Fatal("read-only renewal reconciliation failed", err)
	}
	backup := filepath.Join(privateSnapshotDir(t), "renewal.rwfull")
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
		const recovered = "renewal recovery test password"
		if _, err := RecoverPassword(fresh, code, recovered); err != nil {
			t.Fatal(err)
		}
		rk, ri, err := OpenWithIdentity(fresh, recovered)
		if err != nil {
			t.Fatal(err)
		}
		rr, err := Revision(fresh)
		if err != nil {
			t.Fatal(err)
		}
		s, g, err := ReadStagingOrder(fresh, rk, ri, rr)
		if err != nil || g != 17 || s.RenewalSource != fp {
			t.Fatal("renewal link lost during full recovery")
		}
		if records, g, err := ReadInventory(fresh, rk, ri, rr); err != nil || g != 17 || len(records) != 1 || records[0].Fingerprint != fp || records[0].KeyStatus != "matched" {
			t.Fatal("recovery lost original pair")
		}
		clear(rk)
	}
}
