package inventorystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

func TestAutomationStatusWholeImageLifetimeAndNoMutation(t *testing.T) {
	key, id, _, image, _, fp, at := syntheticCompletion(t)
	defer clear(key)
	original := bytes.Clone(image)
	s, err := ReadAutomationStatus(key, id, image, at.Add(time.Second))
	if err != nil || s.Generation != 13 || s.Request != "close-needed" || s.DNS != "none" || !s.AccountReady || s.DNSSaved || len(s.Certificates) != 1 {
		t.Fatal("legitimate overview refused", err, s)
	}
	r := s.Certificates[0]
	// Fixture validity is 61 minutes (<10d); review halfway, 30m30s after NotBefore.
	if r.Fingerprint != fp || r.Name != "*.example.com" || r.State != "waiting" || r.ReviewAt != at.Add(29*time.Minute+30*time.Second).Format(time.RFC3339) || s.Capacity.EventsFree != 1012 || s.Capacity.EventsReserved != 0 || s.Capacity.ArchivesFree != 32 || s.Capacity.RecordsFree != 499 {
		t.Fatal("incorrect lifetime/headroom", s)
	}
	for _, tc := range []struct {
		at    time.Time
		state string
	}{{at.Add(40 * time.Minute), "due"}, {at.Add(time.Hour), "expired"}} {
		s, err := ReadAutomationStatus(key, id, image, tc.at)
		if err != nil || s.Certificates[0].State != tc.state {
			t.Fatal("review boundary wrong", tc.state, err)
		}
	}
	if !bytes.Equal(image, original) {
		t.Fatal("read mutated the complete image")
	}
	for _, tc := range []struct {
		key, id, image []byte
		at             time.Time
	}{
		{key, id, image, at.Add(-time.Hour)}, {key, id, image, time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC)},
		{key, id, append(bytes.Clone(image), '\n'), at.Add(time.Second)}, {make([]byte, 32), id, image, at.Add(time.Second)},
		{key, make([]byte, 16), image, at.Add(time.Second)}, {key, id, image[:len(image)-1], at.Add(time.Second)},
	} {
		s, err := ReadAutomationStatus(tc.key, tc.id, tc.image, tc.at)
		if err == nil || !reflect.DeepEqual(s, AutomationStatus{}) {
			t.Fatal("invalid source released partial status")
		}
	}
	// A plain imported certificate cannot gain staging renewal authority.
	blank, err := Create(key, id)
	if err != nil {
		t.Fatal(err)
	}
	imported, _, err := Append(key, id, blank, demo(t, "rootwell-demo-certificate.pem"), "private-owner-sentinel", "private-note-sentinel")
	if err != nil {
		t.Fatal(err)
	}
	s, err = ReadAutomationStatus(key, id, imported, time.Now().Add(time.Second))
	if err != nil || len(s.Certificates) != 1 || s.Certificates[0].State != "manual" || s.Certificates[0].ReviewAt != "" || s.Request != "none" {
		t.Fatal("import acquired renewal authority", err)
	}
	public, _ := json.Marshal(s)
	for _, secret := range []string{"private-owner-sentinel", "private-note-sentinel", "PRIVATE KEY", "acme/order"} {
		if bytes.Contains(public, []byte(secret)) {
			t.Fatal("overview exposed notes or internal data")
		}
	}
}

func TestAutomationStatusDNSReservationsWaitAndTerminalMaintenance(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		key, id, image, at := exhaustedDNSFixture(t, cleanup)
		defer clear(key)
		m, _, _ := decode(key, id, image)
		plan, _ := openDNSPlan(key, id, m)
		s, err := ReadAutomationStatus(key, id, image, at)
		reserve, _ := dnsTotalReserve(key, id, m, plan)
		if err != nil || s.DNS != "unknown" || s.DNSWaitUntil != "" || s.Capacity.EventsReserved != reserve || s.Capacity.EventsFree != maxHistory-len(m.History)-reserve || s.Capacity.GenerationsFree != maxGeneration-m.Generation-uint64(reserve) || s.Capacity.BytesFree != maxImage-len(image)-reservedImageBytes(key, id, m) {
			t.Fatal("unresolved work lost reservations", err, s)
		}
		public, _ := json.Marshal(s)
		for _, secret := range []string{configToken, configZoneID, orderURLFixture, plan.Records[0].Owner, plan.Records[0].Value, dnsOwnedID} {
			if bytes.Contains(public, []byte(secret)) {
				t.Fatal("overview leaked credential/ownership")
			}
		}
		for n := 0; n < 6; n++ {
			var result DNSPlanStatus
			image, result, _ = runRecoveryAt(t, key, id, image, at, func(_ func() bool, _ []byte, _ dnsrecord.Scope, s dnsrecord.State, _, read bool, _ func(dnsrecord.State) error) (dnsrecord.State, error) {
				if !read {
					t.Fatal("recovery gained mutation")
				}
				return s, nil
			})
			wait := result.Records[0].Recovery.NotBefore
			s, err = ReadAutomationStatus(key, id, image, at.Add(time.Second))
			if err != nil || n < 5 && (s.DNS != "unknown" || s.DNSWaitUntil != wait) || n == 5 && (s.DNS != "maintenance" || s.DNSWaitUntil != "") {
				t.Fatal("wait/terminal limit misreported", n, err, s)
			}
			at = mustDNSTime(wait)
		}
		// Reading terminal maintenance never resets/advances attempts or the image.
		before := bytes.Clone(image)
		_, err = ReadAutomationStatus(key, id, image, at.Add(time.Hour))
		if err != nil || !bytes.Equal(before, image) {
			t.Fatal("terminal read changed scope", err)
		}
	}
}

func TestAutomationDNSBlockAndClockCannotBecomeReady(t *testing.T) {
	now := "2026-10-26T10:00:00Z"
	base := dnsPlanPayload{PreparedAt: "2026-10-26T09:00:00Z", Records: []dnsPlanRecord{{State: "creating", Retry: providerretry.State{Attempts: 1, LastAt: "2026-10-26T09:00:00Z", NotBefore: "2026-10-26T11:00:00Z"}}}}
	for _, tc := range []struct {
		change      func(*dnsPlanRecord)
		state, wait string
	}{
		{func(r *dnsPlanRecord) {}, "unknown", "2026-10-26T11:00:00Z"},
		{func(r *dnsPlanRecord) { r.Blocked = true }, "maintenance", ""},
		{func(r *dnsPlanRecord) { r.OutcomeAt = "2026-10-26T10:00:01Z" }, "clock-unavailable", ""},
		{func(r *dnsPlanRecord) { r.State = "created" }, "cleanup-needed", ""},
		{func(r *dnsPlanRecord) { r.State = "borrowed" }, "none", ""},
	} {
		p := base
		p.Records = append([]dnsPlanRecord(nil), base.Records...)
		tc.change(&p.Records[0])
		state, wait := dnsAutomationState(p, now)
		if state != tc.state || wait != tc.wait {
			t.Fatal("wrong refusal", state, wait)
		}
	}
}

func FuzzAutomationStatusWholeImage(f *testing.F) {
	f.Add([]byte(`{"body":"","mac":""}`), int64(1793000000))
	f.Add([]byte(strings.Repeat("x", 64)), int64(0))
	f.Fuzz(func(t *testing.T, image []byte, unix int64) {
		if len(image) > 128<<10 {
			t.Skip()
		}
		s, err := ReadAutomationStatus(make([]byte, 32), make([]byte, 16), image, time.Unix(unix, 0))
		if err == nil || !reflect.DeepEqual(s, AutomationStatus{}) {
			t.Fatal("unauthenticated image exposed status")
		}
	})
}

func TestAutomationStatusUnusualImportedNamesRemainBoundedAndManual(t *testing.T) {
	key, id := testIdentity(t)
	defer clear(key)
	keyPair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, name := range []string{strings.Repeat("a", 2000) + ".invalid", "bad\x00name.invalid"} {
		certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic unusual import"}, DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, keyPair.Public(), keyPair)
		if err != nil {
			t.Fatal(err)
		}
		blank, err := Create(key, id)
		if err != nil {
			t.Fatal(err)
		}
		image, _, err := Append(key, id, blank, der, "", "private-note-sentinel")
		if err != nil {
			t.Fatal("legitimate public import refused", err)
		}
		s, err := ReadAutomationStatus(key, id, image, now.Add(time.Second))
		if err != nil || len(s.Certificates) != 1 {
			t.Fatal("unusual name disabled whole overview", err)
		}
		r := s.Certificates[0]
		if r.State != "manual" || r.ReviewAt != "" || !strings.HasPrefix(r.Name, "Saved certificate · ") || len(r.Name) > 255 || strings.Contains(r.Name, name) {
			t.Fatal("unbounded/unsafe imported label escaped", r)
		}
	}
}
