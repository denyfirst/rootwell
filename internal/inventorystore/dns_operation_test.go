package inventorystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

var dnsOwnedID = strings.Repeat("c", 32)

func dnsSuccessfulCreate(t *testing.T) DNSOperation {
	t.Helper()
	return func(permit func() bool, token []byte, scope dnsrecord.Scope, saved dnsrecord.State, cleanup, readOnly bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		if !permit() || string(token) != configToken || scope.ZoneID != configZoneID || scope.ZoneName != "example.com" || scope.Owner == "" || scope.Name != "_acme-challenge.example.com" || saved != (dnsrecord.State{State: "new"}) || cleanup || readOnly {
			t.Fatal("credential or exact first-create scope changed")
		}
		if err := checkpoint(dnsrecord.State{State: "creating"}); err != nil {
			t.Fatal(err)
		}
		if err := checkpoint(dnsrecord.State{State: "creating"}); err == nil {
			t.Fatal("checkpoint replay")
		}
		return dnsrecord.State{State: "created", ID: dnsOwnedID}, nil
	}
}
func dnsRunAt(t *testing.T, key, id, image []byte, index int, mode string, at time.Time, use DNSOperation) ([]byte, DNSPlanStatus, uint64) {
	t.Helper()
	_, g, err := ReadStagingDNSPlan(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	next, a, _, _, err := beginDNSOperationAt(key, id, image, g, index, mode, at)
	if err != nil {
		t.Fatal("legitimate begin", err)
	}
	next, s, g, err := executeStagingDNSAttemptAt(key, id, next, a, func() bool { return true }, use, func() time.Time { return at.Add(time.Second) })
	if err != nil {
		t.Fatal("legitimate result", err)
	}
	old, _, _ := decode(key, id, image)
	current, _, _ := decode(key, id, next)
	before, _ := openDNSPlan(key, id, old)
	if before.Records[index].State != "new" && len(next)+dnsReservedBytes(key, id, current) > len(image)+dnsReservedBytes(key, id, old) {
		t.Fatal("reserved bytes could not fund subsequent intent/outcome growth")
	}
	return next, s, g
}

func TestDNSOperationCreateOwnedCleanupExpiryArchiveAndSecretBoundary(t *testing.T) {
	key, id, image := preparedDNSPlanFixture(t)
	at := time.Now().UTC()
	created, s, g := dnsRunAt(t, key, id, image, 0, "add", at, dnsSuccessfulCreate(t))
	if s.Records[0].State != "created" || s.Records[0].Attempts != 1 || s.Records[0].CleanupAttempts != 0 || g != 11 {
		t.Fatal("exact creation result not saved")
	}
	public, _ := json.Marshal(s)
	m, _, _ := decode(key, id, created)
	p, _ := openDNSPlan(key, id, m)
	for _, secret := range []string{configToken, configZoneID, dnsOwnedID, p.Records[0].Value, p.Records[0].Owner, p.Order} {
		if bytes.Contains(public, []byte(secret)) || bytes.Contains(created, []byte(secret)) {
			t.Fatal("DNS secret escaped encrypted image")
		}
	}
	if status, _, err := ReadNewStagingRequest(key, id, created); err != nil || status.Reason != "dns-cleanup-needed" {
		t.Fatal("owned record abandoned")
	}
	if out, _, _, err := ChangeCloudflareConfig(key, id, created, g, "", "", nil, true); err == nil || out != nil {
		t.Fatal("credential removed before cleanup")
	}
	afterExpiry := mustDNSTime(p.Expires).Add(time.Second)
	if out, a, _, _, err := beginDNSOperationAt(key, id, created, g, 1, "add", afterExpiry); err == nil || out != nil || a != nil {
		t.Fatal("expired new TXT authorized")
	}
	clean, s, g := dnsRunAt(t, key, id, created, 0, "cleanup", afterExpiry, func(permit func() bool, _ []byte, scope dnsrecord.Scope, saved dnsrecord.State, cleanup, readOnly bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		if !permit() || scope.Owner != p.Records[0].Owner || !cleanup || readOnly || saved != (dnsrecord.State{State: "created", ID: dnsOwnedID}) {
			t.Fatal("cleanup lost owned identity/expiry independence")
		}
		if err := checkpoint(dnsrecord.State{State: "deleting", ID: dnsOwnedID}); err != nil {
			t.Fatal(err)
		}
		return dnsrecord.State{State: "deleted"}, nil
	})
	if s.Records[0].State != "deleted" || s.Records[0].CleanupAttempts != 1 {
		t.Fatal("owned cleanup not saved")
	}
	closed, _, g, err := closeStagingRequestAt(key, id, clean, g, afterExpiry.Add(2*time.Second))
	if err != nil {
		t.Fatal("resolved scope failed to archive", err)
	}
	rotated, _, _, err := ChangeCloudflareConfig(key, id, closed, g, configZoneID, "example.com", []byte(strings.Repeat("B", 40)), false)
	if err != nil {
		t.Fatal("resolved archive blocked rotation", err)
	}
	if _, _, err := Open(key, id, rotated); err != nil {
		t.Fatal("historical cleanup invalid after rotation", err)
	}
}

func TestDNSOperationBorrowedNeverCleanupAndLeaseCannotReplay(t *testing.T) {
	key, id, image := preparedDNSPlanFixture(t)
	next, a, _, _, err := BeginStagingDNSOperation(key, id, image, 9, 0, "add")
	if err != nil {
		t.Fatal(err)
	}
	copyLease := *a
	borrowed, s, g, err := ExecuteStagingDNSAttempt(key, id, next, a, func() bool { return true }, func(permit func() bool, _ []byte, _ dnsrecord.Scope, _ dnsrecord.State, cleanup, readOnly bool, _ func(dnsrecord.State) error) (dnsrecord.State, error) {
		if !permit() || cleanup || readOnly {
			t.Fatal("first borrow direction")
		}
		return dnsrecord.State{State: "borrowed"}, nil
	})
	if err != nil || s.Records[0].State != "borrowed" {
		t.Fatal("legitimate existing TXT refused", err)
	}
	if out, _, _, err := ExecuteStagingDNSAttempt(key, id, next, &copyLease, func() bool { return true }, dnsSuccessfulCreate(t)); err == nil || out != nil {
		t.Fatal("copied lease replayed")
	}
	for _, mode := range []string{"cleanup", "check", "add"} {
		if out, a, _, _, err := BeginStagingDNSOperation(key, id, borrowed, g, 0, mode); err == nil || out != nil || a != nil {
			t.Fatal("borrowed record received cleanup/replay authority")
		}
	}
	next, a, _, _, err = BeginStagingDNSOperation(key, id, image, 9, 0, "add")
	if err != nil {
		t.Fatal(err)
	}
	changed, _, err := Append(key, id, next, demo(t, "rootwell-demo-certificate.pem"), "team", "service")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	use := func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
		called = true
		return dnsrecord.State{}, nil
	}
	if out, _, _, err := ExecuteStagingDNSAttempt(key, id, changed, a, func() bool { return true }, use); err == nil || out != nil || called {
		t.Fatal("changed image borrowed token")
	}
	if out, _, _, err := ExecuteStagingDNSAttempt(key, id, next, a, func() bool { return true }, use); err == nil || out != nil || called {
		t.Fatal("failed lease remained reusable")
	}
}

func TestDNSOperationUnknownCreateReadOnlyAfterExpiryAndPersistentWait(t *testing.T) {
	key, id, image := preparedDNSPlanFixture(t)
	at := time.Now().UTC()
	unknown, s, g := dnsRunAt(t, key, id, image, 0, "add", at, func(_ func() bool, _ []byte, _ dnsrecord.Scope, _ dnsrecord.State, _, _ bool, _ func(dnsrecord.State) error) (dnsrecord.State, error) {
		return dnsrecord.State{}, &providerretry.Failure{Hint: providerretry.Hint{NotBefore: at.Add(10 * time.Minute)}}
	})
	if s.Records[0].State != "creating" || s.Records[0].NotBefore < at.Add(10*time.Minute).UTC().Format("2006-01-02T15:04:05Z") {
		t.Fatal("wait not retained")
	}
	if out, a, _, _, err := beginDNSOperationAt(key, id, unknown, g, 0, "check", at.Add(time.Minute)); err == nil || out != nil || a != nil {
		t.Fatal("provider wait skipped")
	}
	m, _, _ := decode(key, id, unknown)
	p, _ := openDNSPlan(key, id, m)
	after := mustDNSTime(p.Expires).Add(time.Second)
	result, s, _ := dnsRunAt(t, key, id, unknown, 0, "check", after, func(permit func() bool, _ []byte, _ dnsrecord.Scope, saved dnsrecord.State, cleanup, readOnly bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		if !permit() || cleanup || !readOnly || saved.State != "creating" {
			t.Fatal("uncertain create gained POST")
		}
		if err := checkpoint(dnsrecord.State{State: "creating"}); err == nil {
			t.Fatal("read-only checkpoint authorized")
		}
		return dnsrecord.State{State: "created", ID: dnsOwnedID}, nil
	})
	if s.Records[0].State != "created" || s.Records[0].Attempts != 2 {
		t.Fatal("same-scope reconciliation failed")
	}
	if _, _, err := Open(key, id, result); err != nil {
		t.Fatal(err)
	}
}

func TestDNSOperationCleanupUnknownNoDeleteReplayAndReservedBudget(t *testing.T) {
	key, id, image := preparedDNSPlanFixture(t)
	at := time.Now().UTC()
	created, _, _ := dnsRunAt(t, key, id, image, 0, "add", at, dnsSuccessfulCreate(t))
	m, _, _ := decode(key, id, created)
	m.Generation = maxGeneration - 13
	m.History = nil
	created, _ = encode(key, m)
	if _, _, err := Open(key, id, created); err != nil {
		t.Fatal("fully reserved cleanup capacity refused", err)
	}
	pending, s, g := dnsRunAt(t, key, id, created, 0, "cleanup", at.Add(2*time.Second), func(_ func() bool, _ []byte, _ dnsrecord.Scope, _ dnsrecord.State, cleanup, readOnly bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		if !cleanup || readOnly {
			t.Fatal("first cleanup direction")
		}
		if err := checkpoint(dnsrecord.State{State: "deleting", ID: dnsOwnedID}); err != nil {
			t.Fatal(err)
		}
		return dnsrecord.State{}, errors.New("private-provider-sentinel")
	})
	if s.Records[0].State != "deleting" || s.Records[0].CleanupAttempts != 1 || s.Records[0].Attempts != 1 {
		t.Fatal("cleanup intent/budget lost")
	}
	for i := 2; i <= 6; i++ {
		at = mustDNSTime(s.Records[0].CleanupNotBefore)
		pending, s, g = dnsRunAt(t, key, id, pending, 0, "check", at, func(permit func() bool, _ []byte, _ dnsrecord.Scope, saved dnsrecord.State, cleanup, readOnly bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
			if !permit() || !cleanup || !readOnly || saved.State != "deleting" || saved.ID != dnsOwnedID {
				t.Fatal("uncertain deletion replayed")
			}
			if err := checkpoint(saved); err == nil {
				t.Fatal("deletion read gained write")
			}
			return saved, nil
		})
		if s.Records[0].CleanupAttempts != i {
			t.Fatal("separate count lost")
		}
	}
	if out, a, _, _, err := beginDNSOperationAt(key, id, pending, g, 0, "check", at.Add(time.Hour)); err == nil || out != nil || a != nil {
		t.Fatal("exhausted cleanup reset")
	}
	if result, _, err := ReadNewStagingRequest(key, id, pending); err != nil || result.Reason != "dns-cleanup-needed" {
		t.Fatal("exhausted unknown ownership abandoned", err)
	}
}

func TestDNSOperationMalformedOwnedResultsAndPostCallbackRevocationRefuse(t *testing.T) {
	for _, test := range []string{"no-intent", "foreign-id", "borrow-after-intent", "revoke", "invalid-wait"} {
		t.Run(test, func(t *testing.T) {
			key, id, image := preparedDNSPlanFixture(t)
			next, a, _, _, err := BeginStagingDNSOperation(key, id, image, 9, 0, "add")
			if err != nil {
				t.Fatal(err)
			}
			allowed := true
			out, s, _, err := ExecuteStagingDNSAttempt(key, id, next, a, func() bool { return allowed }, func(_ func() bool, _ []byte, _ dnsrecord.Scope, _ dnsrecord.State, _, _ bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
				if test == "no-intent" {
					return dnsrecord.State{State: "created", ID: dnsOwnedID}, nil
				}
				if err := checkpoint(dnsrecord.State{State: "creating"}); err != nil {
					t.Fatal(err)
				}
				switch test {
				case "foreign-id":
					return dnsrecord.State{State: "created", ID: "../foreign"}, nil
				case "borrow-after-intent":
					return dnsrecord.State{State: "borrowed"}, nil
				case "revoke":
					allowed = false
					return dnsrecord.State{State: "created", ID: dnsOwnedID}, nil
				default:
					return dnsrecord.State{}, &providerretry.Failure{Hint: providerretry.Hint{Blocked: true}}
				}
			})
			if test == "invalid-wait" {
				if err != nil || !s.Records[0].Blocked || s.Records[0].State != "creating" {
					t.Fatal("invalid provider hint did not block")
				}
				return
			}
			if err == nil || out != nil || s.Prepared {
				t.Fatal("malformed/revoked callback published ownership")
			}
		})
	}
	key, id, image := preparedDNSPlanFixture(t)
	created, _, _ := dnsRunAt(t, key, id, image, 0, "add", time.Now().UTC(), dnsSuccessfulCreate(t))
	for _, change := range []func(*dnsPlanRecord){func(r *dnsPlanRecord) { r.ID = "" }, func(r *dnsPlanRecord) { r.State = "deleted" }, func(r *dnsPlanRecord) { r.Cleanup = &providerretry.State{} }, func(r *dnsPlanRecord) { r.CheckedAt = "2026-02-30T00:00:00Z" }, func(r *dnsPlanRecord) { r.CleanupBlocked = true }} {
		m, _, _ := decode(key, id, created)
		p, _ := openDNSPlan(key, id, m)
		change(&p.Records[0])
		plain, _ := json.Marshal(p)
		k, _ := dnsPlanKey(key, id)
		item := m.DNSPlans[0]
		item.Ciphertext, _ = inventoryseal.Seal(k, attachmentContext(id, item), plain)
		clear(k)
		clear(plain)
		m.DNSPlans = []sealedRecord{item}
		bad, _ := encode(key, m)
		if records, g, err := Open(key, id, bad); err == nil || records != nil || g != 0 {
			t.Fatal("malformed owned state exposed partial image")
		}
	}
}

func TestDNSOperationClockCannotGoBackBeforeSavedOutcome(t *testing.T) {
	key, id, image := preparedDNSPlanFixture(t)
	at := time.Now().UTC()
	next, a, _, _, err := beginDNSOperationAt(key, id, image, 9, 0, "add", at)
	if err != nil {
		t.Fatal(err)
	}
	deferred, _, g, err := executeStagingDNSAttemptAt(key, id, next, a, func() bool { return true }, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
		return dnsrecord.State{}, errors.New("synthetic failure")
	}, func() time.Time { return at.Add(3 * time.Minute) })
	if err != nil {
		t.Fatal("late outcome not saved", err)
	}
	if out, a, _, _, err := beginDNSOperationAt(key, id, deferred, g, 0, "check", at.Add(2*time.Minute)); err == nil || out != nil || a != nil {
		t.Fatal("clock reversal before outcome granted network authority")
	}
}
