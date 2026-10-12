//go:build linux

package instanceaccess

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func TestLinuxCertificateTransactionDurableIntentNoReplayAndCheckedRead(t *testing.T) {
	path, _, _, key, id, revision := readyIssuanceStore(t)
	defer clear(key)
	store := filepath.Join(filepath.Dir(path), inventoryName)
	allow := func() bool { return true }
	calls := 0
	var savedPrivate, savedCSR []byte
	defer func() { clear(savedPrivate); clear(savedCSR) }()
	use := func(_ crypto.Signer, account, order, expires string, _ []string, private, csr []byte, readOnly bool) (acmestaging.CertificateObservation, error) {
		calls++
		image, err := readInventory(store)
		s, gen, statusErr := inventorystore.ReadStagingIssuance(key, id, image)
		if err != nil || statusErr != nil || gen != 12 || s.State != "issuance-pending" || readOnly || account != durableAccount || order != durableOrder || len(private) == 0 || len(csr) == 0 {
			t.Fatal("network before durable exact intent")
		}
		savedPrivate, savedCSR = bytes.Clone(private), bytes.Clone(csr)
		return acmestaging.CertificateObservation{}, errors.New("provider private sentinel")
	}
	if s, g, err := RunStagingCertificate(path, key, id, revision, 11, false, allow, use); err != inventorystore.ErrIssuanceUncertain || s.State != "" || g != 0 || calls != 1 {
		t.Fatal("unknown operation returned success/provider error")
	}
	before, _ := readInventory(store)
	for _, tc := range []struct {
		gen     uint64
		refresh bool
		permit  func() bool
	}{{12, false, allow}, {11, true, allow}, {12, true, nil}, {12, true, func() bool { return false }}} {
		if s, g, err := RunStagingCertificate(path, key, id, revision, tc.gen, tc.refresh, tc.permit, use); err == nil || s.State != "" || g != 0 || calls != 1 {
			t.Fatal("stale/duplicate authority contacted CA")
		}
	}
	for _, observation := range []acmestaging.CertificateObservation{{State: "processing"}, {State: "processing", Expires: "2020-01-01T00:00:00Z"}, {State: "processing", Expires: "9999-01-01T00:00:00Z"}, {State: "certificate-received", DER: [][]byte{[]byte("malformed certificate")}, Expires: durableDNS().Expires}, {State: "valid", Expires: durableDNS().Expires}, {State: "processing", DER: [][]byte{[]byte("unexpected bytes")}, Expires: durableDNS().Expires}} {
		if s, g, err := RunStagingCertificate(path, key, id, revision, 12, true, allow, func(_ crypto.Signer, _, _, _ string, _ []string, private, csr []byte, readOnly bool) (acmestaging.CertificateObservation, error) {
			if !readOnly || !bytes.Equal(private, savedPrivate) || !bytes.Equal(csr, savedCSR) {
				t.Fatal("read changed exact key/CSR or replayed finalize")
			}
			return observation, nil
		}); err == nil || s.State != "" || g != 0 {
			t.Fatal("forged/untrusted observation accepted")
		}
		after, _ := readInventory(store)
		if !bytes.Equal(before, after) {
			t.Fatal("refused read changed durable intent")
		}
	}
	permitted := true
	if _, _, err := RunStagingCertificate(path, key, id, revision, 12, true, func() bool { return permitted }, func(_ crypto.Signer, _, _, expiry string, _ []string, _, _ []byte, _ bool) (acmestaging.CertificateObservation, error) {
		permitted = false
		return acmestaging.CertificateObservation{State: "processing", Expires: expiry}, nil
	}); err == nil {
		t.Fatal("revoked result published")
	}
	s, g, err := RunStagingCertificate(path, key, id, revision, 12, true, allow, func(_ crypto.Signer, _, _, expiry string, _ []string, private, csr []byte, readOnly bool) (acmestaging.CertificateObservation, error) {
		if !readOnly || !bytes.Equal(private, savedPrivate) || !bytes.Equal(csr, savedCSR) {
			t.Fatal("read scope changed")
		}
		return acmestaging.CertificateObservation{State: "processing", Expires: expiry}, nil
	})
	if err != nil || g != 13 || s.State != "awaiting-certificate" {
		t.Fatal("checked same-order processing read refused")
	}
	if st, err := os.Stat(store); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal("unsafe private image permissions")
	}
}

func TestLinuxCertificateTransactionFirstProcessingAndWriterExclusion(t *testing.T) {
	path, _, _, key, id, revision := readyIssuanceStore(t)
	defer clear(key)
	calls := 0
	allow := func() bool { return true }
	use := func(_ crypto.Signer, _, _, expiry string, _ []string, _, _ []byte, readOnly bool) (acmestaging.CertificateObservation, error) {
		calls++
		if readOnly {
			t.Fatal("first attempt lost direction")
		}
		return acmestaging.CertificateObservation{State: "processing", Expires: expiry}, nil
	}
	if err := withAccessWriteLock(path, func() error {
		if _, _, err := RunStagingCertificate(path, key, id, revision, 11, false, allow, use); err == nil || calls != 0 {
			t.Fatal("second writer gained CA authority")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, g, err := RunStagingCertificate(path, key, id, revision, 11, false, allow, use)
	if err != nil || g != 13 || s.State != "awaiting-certificate" || s.Expires == "" || calls != 1 {
		t.Fatal("first processing did not preserve durable no-replay state")
	}
	if _, _, err := RunStagingCertificate(path, key, id, revision, 13, false, allow, use); err == nil || calls != 1 {
		t.Fatal("processing replayed finalize")
	}
}

func TestLinuxCertificateTransactionSyntheticAcceptanceAtomicCommitAndLateRefusal(t *testing.T) {
	// The child verifies a synthetic issuer at the unexported model seam. This
	// transaction seam cannot change production trust or prove live CA success.
	fixturePath := filepath.Join(privateSnapshotDir(t), "synthetic-completion.json")
	command := exec.Command("go", "test", "../inventorystore", "-run=^TestGenerateSyntheticCompletionForIntegration$", "-count=1")
	command.Env = append(os.Environ(), "ROOTWELL_TEST_COMPLETION_FIXTURE="+fixturePath)
	if err := command.Run(); err != nil {
		t.Fatal("private synthetic fixture failed")
	}
	body, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	var f struct {
		Key, ID, Image, Pending []byte
		Chain                   [][]byte
		Fingerprint             string
	}
	if json.Unmarshal(body, &f) != nil {
		t.Fatal("invalid fixture")
	}
	defer clear(f.Key)
	access, err := seal(f.Key, "synthetic transaction password", ready, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateSnapshotDir(t), "access.json")
	if err := os.WriteFile(path, access, 0o600); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(filepath.Dir(path), inventoryName)
	if err := createInventory(store, f.Pending); err != nil {
		t.Fatal(err)
	}
	rev, err := Revision(path)
	if err != nil {
		t.Fatal(err)
	}
	allow := func() bool { return true }
	use := func(_ crypto.Signer, _, _, expires string, _ []string, _, _ []byte, readOnly bool) (acmestaging.CertificateObservation, error) {
		if !readOnly {
			t.Fatal("recovered intent finalized again")
		}
		der := make([][]byte, len(f.Chain))
		for i := range der {
			der[i] = bytes.Clone(f.Chain[i])
		}
		return acmestaging.CertificateObservation{State: "certificate-received", DER: der, Expires: expires}, nil
	}
	// Real entry still refuses the fixture's independently generated issuer.
	if s, g, err := RunStagingCertificate(path, f.Key, f.ID, rev, 12, true, allow, use); err == nil || s.State != "" || g != 0 {
		t.Fatal("production accepted unpinned synthetic issuer")
	}
	permitted := true
	finish := func(key, id, image []byte, gen uint64, response [][]byte) ([]byte, inventorystore.IssuanceStatus, uint64, error) {
		if !bytes.Equal(key, f.Key) || !bytes.Equal(id, f.ID) || !bytes.Equal(image, f.Pending) || gen != 12 || len(response) != len(f.Chain) {
			t.Fatal("transaction lost exact receipt/image binding")
		}
		for i := range response {
			if !bytes.Equal(response[i], f.Chain[i]) {
				t.Fatal("receipt differs")
			}
		}
		s, g, err := inventorystore.ReadStagingIssuance(key, id, f.Image)
		return bytes.Clone(f.Image), s, g, err
	}
	late := func(k, id, image []byte, g uint64, der [][]byte) ([]byte, inventorystore.IssuanceStatus, uint64, error) {
		next, s, gen, err := finish(k, id, image, g, der)
		permitted = false
		return next, s, gen, err
	}
	if s, g, err := runStagingCertificate(path, f.Key, f.ID, rev, 12, true, func() bool { return permitted }, use, late); err == nil || s.State != "" || g != 0 {
		t.Fatal("late cancelled acceptance published")
	}
	after, _ := readInventory(store)
	if !bytes.Equal(after, f.Pending) {
		t.Fatal("late refusal changed durable intent")
	}
	s, g, err := runStagingCertificate(path, f.Key, f.ID, rev, 12, true, allow, use, finish)
	if err != nil || g != 13 || s.State != "certificate-saved" {
		t.Fatal("valid atomic transaction refused")
	}
	after, _ = readInventory(store)
	if !bytes.Equal(after, f.Image) {
		t.Fatal("complete accepted image not atomically saved")
	}
	records, gen, err := ReadInventory(path, f.Key, f.ID, rev)
	if err != nil || gen != 13 || len(records) != 1 || !records[0].HasPrivateKey || records[0].StagingOrigin == nil {
		t.Fatal("pair/provenance missing after transaction")
	}
	for _, refresh := range []bool{false, true} {
		if _, _, err := RunStagingCertificate(path, f.Key, f.ID, rev, 13, refresh, allow, use); err == nil {
			t.Fatal("completed transaction regained network authority")
		}
	}
}
