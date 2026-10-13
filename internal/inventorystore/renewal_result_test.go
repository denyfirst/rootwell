package inventorystore

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func assertRenewalResult(t *testing.T, key, id, image []byte, gen uint64, originalFP, newFP string) {
	t.Helper()
	before := slices.Clone(image)
	result, g, err := ReadStagingRenewalResult(key, id, image, gen)
	if err != nil || result == nil || g != gen || result.OriginalFingerprint != originalFP || result.NewFingerprint != newFP {
		t.Fatal("completed renewal comparison unavailable", err)
	}
	records, _, err := Open(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	var oldDER, newDER []byte
	for _, record := range records {
		if record.Fingerprint == originalFP {
			oldDER = record.DER
		}
		if record.Fingerprint == newFP {
			newDER = record.DER
		}
	}
	comparison, err := publicinventory.Compare(oldDER, newDER)
	if err != nil || result.OriginalExpiry != comparison.OldExpiry || result.NewExpiry != comparison.NewExpiry || result.ExpiryExtended != comparison.ExpiryExtended {
		t.Fatal("result fabricated certificate dates")
	}
	encoded, err := json.Marshal(result)
	var fields map[string]json.RawMessage
	if err != nil || json.Unmarshal(encoded, &fields) != nil || len(fields) != 5 || len(encoded) > 1024 || bytes.Contains(encoded, []byte("PRIVATE")) || bytes.Contains(encoded, []byte("acme/order")) || !bytes.Equal(before, image) {
		t.Fatal("result leaks, exceeds its bound or mutates custody")
	}
	// Deleting the newly saved pair is explicit; it must remove the result,
	// never fabricate a successful comparison from its public tombstone.
	deleted, deletedGen, err := DeleteRecord(key, id, image, newFP, gen)
	if err != nil {
		t.Fatal(err)
	}
	if s, g, err := ReadStagingRenewalResult(key, id, deleted, deletedGen); err != nil || s != nil || g != deletedGen {
		t.Fatal("deleted renewal exposed a saved result")
	}
}

func completedRenewalResultFixture(t *testing.T, lifetime time.Duration) (key, id, image []byte, originalFP, newFP string, gen uint64) {
	t.Helper()
	key, id, _, image, originalFP = renewalFixture(t)
	gen = 15
	info := orderInstructionsFixture()
	info.URL = acmeorder.Origin + "/acme/order/1234/9999"
	var err error
	image, _, gen, err = UpdateStagingOrder(key, id, image, gen, info.URL, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = UpdateStagingOrder(key, id, image, gen, "", &info, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = UpdateStagingOrder(key, id, image, gen, "", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = BeginStagingValidation(key, id, image, gen, false)
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = FinishStagingValidation(key, id, image, gen, acmeorder.Validation{URL: info.URL, Expires: info.Expires, OrderStatus: "ready", Statuses: []string{"valid", "valid"}})
	if err != nil {
		t.Fatal(err)
	}
	image, _, gen, err = PrepareStagingCertificateRequest(key, id, image, gen)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _, gen, err = BeginStagingIssuance(key, id, image, gen, false)
	if err != nil {
		t.Fatal(err)
	}
	image, newFP, gen = completeRenewalWithLifetime(t, key, id, image, gen, lifetime)
	return
}

func TestRenewalResultReportsShorterLifetimeWithoutAssumingExtension(t *testing.T) {
	for _, lifetime := range []time.Duration{30 * time.Minute, 2 * time.Hour} {
		key, id, image, oldFP, newFP, gen := completedRenewalResultFixture(t, lifetime)
		assertRenewalResult(t, key, id, image, gen, oldFP, newFP)
		result, _, err := ReadStagingRenewalResult(key, id, image, gen)
		clear(key)
		if err != nil || result == nil || result.ExpiryExtended != (lifetime > time.Hour) {
			t.Fatal("renewal assumed extension instead of comparing dates")
		}
	}
}

// Private ephemeral fixture only: real encrypted image, synthetic CA, no runtime
// trust override. A child test is necessary across Go internal package boundaries.
func TestGenerateSyntheticRenewalForIntegration(t *testing.T) {
	path := os.Getenv("ROOTWELL_TEST_COMPLETION_FIXTURE")
	if path == "" {
		t.Skip("private renewal fixture not requested")
	}
	if !filepath.IsAbs(path) || filepath.Base(path) != "synthetic-completion.json" {
		t.Fatal("fixture destination refused")
	}
	key, id, image, fp, _, _ := completedRenewalResultFixture(t, 2*time.Hour)
	defer clear(key)
	body, err := json.Marshal(struct {
		Key, ID, Image []byte
		Fingerprint    string
	}{key, id, image, fp})
	defer clear(body)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal("fixture creation refused")
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		t.Fatal("fixture write failed")
	}
}

func TestRenewalResultRefusesStaleTamperedAndIncompleteWithoutPartialOutput(t *testing.T) {
	key, id, closed, pending, _ := renewalFixture(t)
	defer clear(key)
	for _, tc := range []struct {
		image []byte
		gen   uint64
	}{{closed, 14}, {pending, 15}} {
		if result, g, err := ReadStagingRenewalResult(key, id, tc.image, tc.gen); err != nil || result != nil || g != tc.gen {
			t.Fatal("incomplete/closed scope reported a renewal result")
		}
	}
	for _, expected := range []uint64{0, 14, 16} {
		if result, g, err := ReadStagingRenewalResult(key, id, pending, expected); err == nil || result != nil || g != 0 {
			t.Fatal("stale selection exposed partial result")
		}
	}
	for _, image := range [][]byte{nil, []byte("secret-sentinel"), pending[:len(pending)-1]} {
		if result, g, err := ReadStagingRenewalResult(key, id, image, 15); err == nil || result != nil || g != 0 {
			t.Fatal("malformed image exposed partial result")
		}
	}
	wrong := slices.Clone(key)
	wrong[0] ^= 1
	defer clear(wrong)
	if result, g, err := ReadStagingRenewalResult(wrong, id, pending, 15); err == nil || result != nil || g != 0 {
		t.Fatal("wrong key exposed result")
	}
	// Ordinary checked issuance is not a renewal even though a pair is saved.
	otherKey, otherID, _, done, _, _, _ := syntheticCompletion(t)
	defer clear(otherKey)
	if result, g, err := ReadStagingRenewalResult(otherKey, otherID, done, 13); err != nil || result != nil || g != 13 {
		t.Fatal("ordinary issuance relabeled renewal")
	}
}
