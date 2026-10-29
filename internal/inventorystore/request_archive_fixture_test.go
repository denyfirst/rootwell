package inventorystore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
)

// Private synthetic model fixture for Linux writer/API tests. It has no runtime
// entry point, network capability, trusted certificate receipt or clock override.
func TestGenerateRequestArchiveFixture(t *testing.T) {
	source := os.Getenv("ROOTWELL_REQUEST_ARCHIVE_FIXTURE")
	if source == "" {
		t.Skip("private synthetic fixture not requested")
	}
	generateRequestArchiveFixture(t, source)
}

func generateRequestArchiveFixture(t *testing.T, source string) {
	t.Helper()
	if !filepath.IsAbs(source) || filepath.Base(source) != "synthetic-request-archive-input.json" {
		t.Fatal("fixture input refused")
	}
	body, err := os.ReadFile(source)
	defer clear(body)
	var input struct{ Key, ID, Image []byte }
	if err != nil || len(body) > 32768 || json.Unmarshal(body, &input) != nil {
		t.Fatal("private fixture invalid")
	}
	defer clear(input.Key)
	defer clear(input.ID)
	defer clear(input.Image)
	m, _, err := decode(input.Key, input.ID, input.Image)
	if err != nil || len(m.ACMEOrders) != 0 || closedRequestCount(m) != 0 {
		t.Fatal("fixture requires unused registered store")
	}
	p, err := openAccountPayload(input.Key, input.ID, m)
	defer clear(p.PrivateKey)
	if err != nil || p.Registration == nil || p.Registration.State != "registered" {
		t.Fatal("fixture account invalid")
	}
	past := time.Now().UTC().Truncate(time.Second).Add(-3 * time.Hour)
	p.PreparedAt = past.Format(time.RFC3339)
	p.Registration.StartedAt = past.Add(time.Second).Format(time.RFC3339)
	p.Registration.RegisteredAt = past.Add(2 * time.Second).Format(time.RFC3339)
	image, _, _, err := sealRegistration(input.Key, input.ID, m, p, "acme-account-registered")
	if err != nil {
		t.Fatal("fixture account rebase", err)
	}
	account, _, err := ReadStagingAccount(input.Key, input.ID, image)
	if err != nil {
		t.Fatal(err)
	}
	at := past.Add(time.Hour)
	for i := 0; i < minClosedRequestArchive; i++ {
		m, _, err = decode(input.Key, input.ID, image)
		if err != nil {
			t.Fatal(err)
		}
		info := orderInstructionsFixture()
		url := acmeorder.Origin + fmt.Sprintf("/acme/order/1234/%d", 70000+i)
		order := orderPayload{State: "dns-ready", Fingerprint: account.Fingerprint, Started: at.Format(time.RFC3339), Domains: []string{"*.example.com", "example.com"}, URL: url, Expires: at.Add(time.Second).Format(time.RFC3339), Records: info.Records}
		var g uint64
		image, _, g, err = sealOrder(input.Key, input.ID, m, order, "acme-dns-prepared")
		if err != nil {
			t.Fatal("fixture scope", err)
		}
		image, _, _, err = closeStagingRequestAt(input.Key, input.ID, image, g, at.Add(time.Second))
		if err != nil {
			t.Fatal("fixture closed scope", err)
		}
		at = at.Add(2 * time.Second)
	}
	defer clear(image)
	if status, err := ReadRequestArchive(input.Key, input.ID, image); err != nil || !status.CanArchive || status.Active != 16 {
		t.Fatal("synthetic archive status", err)
	}
	destination := filepath.Join(filepath.Dir(source), "synthetic-request-archive-output.json")
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(image); err != nil {
		t.Fatal(err)
	}
}

func TestRequestArchiveSyntheticFixtureRoundTrip(t *testing.T) {
	key, id, image := registeredOrderFixture(t)
	defer clear(key)
	dir := t.TempDir()
	input := filepath.Join(dir, "synthetic-request-archive-input.json")
	body, err := json.Marshal(struct{ Key, ID, Image []byte }{key, id, image})
	defer clear(body)
	if err != nil || os.WriteFile(input, body, 0600) != nil {
		t.Fatal("fixture input")
	}
	generateRequestArchiveFixture(t, input)
	filled, err := os.ReadFile(filepath.Join(dir, "synthetic-request-archive-output.json"))
	defer clear(filled)
	if err != nil {
		t.Fatal(err)
	}
	status, err := ReadRequestArchive(key, id, filled)
	if err != nil || status.Active != 16 {
		t.Fatal("fixture status", err)
	}
	next, s, err := ArchiveClosedRequests(key, id, filled, status.Generation)
	if err != nil || s.Archived != 16 || s.Active != 0 {
		t.Fatal("canonical current-clock fixture repack refused", err)
	}
	defer clear(next)
}
