package inventorystore

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

func blockedDNSFixture(t *testing.T, cleanup bool) ([]byte, []byte, []byte, time.Time) {
	t.Helper()
	key, id, image := preparedDNSPlanFixture(t)
	at := time.Now().UTC().Truncate(time.Second)
	if cleanup {
		image, _, _ = dnsRunAt(t, key, id, image, 0, "add", at, dnsSuccessfulCreate(t))
		at = at.Add(2 * time.Second)
	}
	mode := "add"
	if cleanup {
		mode = "cleanup"
	}
	image, s, _ := dnsRunAt(t, key, id, image, 0, mode, at, func(_ func() bool, _ []byte, _ dnsrecord.Scope, _ dnsrecord.State, c, read bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		state := dnsrecord.State{State: "creating"}
		if c {
			state = dnsrecord.State{State: "deleting", ID: dnsOwnedID}
		}
		if read || checkpoint(state) != nil {
			t.Fatal("fixture mutation intent")
		}
		return dnsrecord.State{}, &providerretry.Failure{Hint: providerretry.Hint{Blocked: true}}
	})
	if s.Records[0].Maintenance == nil {
		t.Fatal("terminal maintenance guidance absent")
	}
	return key, id, image, mustDNSTime(s.Records[0].Maintenance.NotBefore)
}

func TestDNSMaintenanceSeparateReadOnlyAuthorityPreservesTerminalPolicy(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "creation", true: "deletion"}[cleanup], func(t *testing.T) {
			key, id, image, at := blockedDNSFixture(t, cleanup)
			before := bytes.Clone(image)
			m, _, _ := decode(key, id, image)
			p, _ := openDNSPlan(key, id, m)
			old := p.Records[0]
			for _, mode := range []string{"add", "check", "recover", "cleanup"} {
				if out, a, _, _, err := beginDNSOperationAt(key, id, image, m.Generation, 0, mode, at); err == nil || out != nil || a != nil {
					t.Fatal("old terminal policy revived", mode)
				}
			}
			if out, a, _, _, err := beginDNSOperationAt(key, id, image, m.Generation, 0, "maintenance", at.Add(-time.Second)); err == nil || out != nil || a != nil {
				t.Fatal("known wait bypassed")
			}
			pending, a, _, g, err := beginDNSOperationAt(key, id, image, m.Generation, 0, "maintenance", at)
			if err != nil || g != m.Generation+1 {
				t.Fatal("valid maintenance refused", err)
			}
			calls := 0
			tick := at
			next, status, g, err := executeStagingDNSAttemptAt(key, id, pending, a, func() bool { return true }, func(permit func() bool, token []byte, scope dnsrecord.Scope, saved dnsrecord.State, c, read bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
				calls++
				if !permit() || !read || c != cleanup || string(token) != configToken || scope.Owner != old.Owner || scope.Value != old.Value || scope.Name != old.Name {
					t.Fatal("maintenance widened authority")
				}
				if checkpoint(saved) == nil {
					t.Fatal("maintenance checkpoint authorised mutation")
				}
				if cleanup {
					return dnsrecord.State{State: "deleted"}, nil
				}
				return dnsrecord.State{State: "created", ID: dnsOwnedID}, nil
			}, func() time.Time { tick = tick.Add(time.Second); return tick })
			if err != nil || calls != 1 || !bytes.Equal(image, before) {
				t.Fatal("maintenance result failed or changed input", err)
			}
			nm, _, err := decode(key, id, next)
			if err != nil {
				t.Fatal(err)
			}
			np, _ := openDNSPlan(key, id, nm)
			r := np.Records[0]
			if r.Retry != old.Retry || r.Blocked != old.Blocked || !reflect.DeepEqual(r.Cleanup, old.Cleanup) || r.CleanupBlocked != old.CleanupBlocked || !reflect.DeepEqual(r.Recovery, old.Recovery) || !reflect.DeepEqual(r.CleanupRecovery, old.CleanupRecovery) || !maintenanceResolved(r, cleanup) {
				t.Fatal("old counters/flags reset or resolution unproved")
			}
			if status.Records[0].Maintenance != nil || status.Records[0].Blocked || status.Records[0].CleanupBlocked {
				t.Fatal("resolved phase exposes active block")
			}
			if _, _, _, err := executeStagingDNSAttemptAt(key, id, pending, a, func() bool { return true }, dnsSuccessfulCreate(t), func() time.Time { return at }); err == nil {
				t.Fatal("maintenance lease replayed")
			}
			if !cleanup {
				if out, _, _, _, err := beginDNSOperationAt(key, id, next, g, 0, "cleanup", tick.Add(time.Second)); err != nil || out == nil {
					t.Fatal("proved owned creation cannot enter separate cleanup", err)
				}
			}
		})
	}
}

func TestDNSMaintenanceUnknownAndRevocationRetainIntentWaitAndCounters(t *testing.T) {
	key, id, image, at := blockedDNSFixture(t, false)
	_, g, _ := ReadStagingDNSPlan(key, id, image)
	pending, a, _, pg, err := beginDNSOperationAt(key, id, image, g, 0, "maintenance", at)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if out, _, _, err := executeStagingDNSAttemptAt(key, id, pending, a, func() bool { return false }, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
		called = true
		return dnsrecord.State{}, nil
	}, func() time.Time { return at }); err == nil || out != nil || called {
		t.Fatal("revoked maintenance reached provider")
	}
	// A crash consumes its attempt and day wait; there is no retirement/reset.
	if out, _, _, _, err := beginDNSOperationAt(key, id, pending, pg, 0, "maintenance", at.Add(time.Hour)); err == nil || out != nil {
		t.Fatal("lost intent retried early")
	}
	nextIntent, a, _, _, err := beginDNSOperationAt(key, id, pending, pg, 0, "maintenance", at.Add(24*time.Hour))
	if err != nil {
		t.Fatal("fresh later operator permission refused", err)
	}
	next, s, g, err := executeStagingDNSAttemptAt(key, id, nextIntent, a, func() bool { return true }, func(_ func() bool, _ []byte, _ dnsrecord.Scope, saved dnsrecord.State, _ bool, read bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
		if !read || checkpoint(saved) == nil {
			t.Fatal("read-only guard missing")
		}
		return saved, nil
	}, func() time.Time { return at.Add(24*time.Hour + time.Second) })
	if err != nil || s.Records[0].State != "creating" || s.Records[0].Maintenance == nil || s.Records[0].Maintenance.Attempts != 2 {
		t.Fatal("empty listing became success or count reset", err)
	}
	m, _, _ := decode(key, id, next)
	p, _ := openDNSPlan(key, id, m)
	if reason, err := closeEligibility(key, id, m, at.Add(25*time.Hour).Format(time.RFC3339)); err != nil || reason != "dns-cleanup-needed" {
		t.Fatal("unknown ownership silently abandoned", reason, err)
	}
	if p.Records[0].Retry.Attempts != 1 || !p.Records[0].Blocked {
		t.Fatal("ordinary policy reset")
	}
	// Stale, missing consent (API), malformed or forged receipts never mint a grant.
	if out, _, _, _, err := beginDNSOperationAt(key, id, next, g-1, 0, "maintenance", at.Add(48*time.Hour)); !errors.Is(err, ErrStaleGeneration) || out != nil {
		t.Fatal("stale maintenance admitted")
	}
	for _, edit := range []func(*dnsPlanRecord){
		func(r *dnsPlanRecord) { r.Maintenance.Resolved = true },
		func(r *dnsPlanRecord) { r.Maintenance.Attempts = 0 },
		func(r *dnsPlanRecord) { r.Maintenance.Attempts = maxDNSMaintenance + 1 },
		func(r *dnsPlanRecord) { r.Maintenance.NotBefore = r.Maintenance.LastAt },
		func(r *dnsPlanRecord) { r.Maintenance.OutcomeAt = "" },
		func(r *dnsPlanRecord) { r.Blocked = false },
	} {
		nm, _, _ := decode(key, id, next)
		np, _ := openDNSPlan(key, id, nm)
		edit(&np.Records[0])
		bad, _, _, e := sealDNSPlan(key, id, nm, np, "acme-dns-maintenance-result")
		if e == nil || bad != nil {
			t.Fatal("malformed or forged maintenance receipt accepted")
		}
	}
}

func TestDNSMaintenanceNotAnAlternativeToOrdinaryChecksAndBadHintsDelay(t *testing.T) {
	key, id, image, at := exhaustedDNSFixture(t, false)
	_, g, _ := ReadStagingDNSPlan(key, id, image)
	if out, _, _, _, err := beginDNSOperationAt(key, id, image, g, 0, "maintenance", at.Add(10*24*time.Hour)); err == nil || out != nil {
		t.Fatal("maintenance bypassed available recovery")
	}
	for i := 0; i < 6; i++ {
		var s DNSPlanStatus
		image, s, _ = runRecoveryAt(t, key, id, image, at, func(_ func() bool, _ []byte, _ dnsrecord.Scope, s dnsrecord.State, _ bool, _ bool, _ func(dnsrecord.State) error) (dnsrecord.State, error) {
			return s, nil
		})
		at = mustDNSTime(s.Records[0].Recovery.NotBefore)
	}
	status, g, err := ReadStagingDNSPlan(key, id, image)
	if err != nil || status.Records[0].Maintenance == nil {
		t.Fatal("exhausted recovery has no maintenance route", err)
	}
	due := mustDNSTime(status.Records[0].Maintenance.NotBefore)
	if out, _, _, _, err := beginDNSOperationAt(key, id, image, g, 0, "maintenance", due); err != nil || out == nil {
		t.Fatal("separate maintenance unavailable after exhausted recovery", err)
	}
	key, id, image, at = blockedDNSFixture(t, false)
	_, g, _ = ReadStagingDNSPlan(key, id, image)
	pending, a, _, _, err := beginDNSOperationAt(key, id, image, g, 0, "maintenance", at)
	if err != nil {
		t.Fatal(err)
	}
	_, s, _, err := executeStagingDNSAttemptAt(key, id, pending, a, func() bool { return true }, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
		return dnsrecord.State{}, &providerretry.Failure{Hint: providerretry.Hint{Blocked: true}}
	}, func() time.Time { return at.Add(time.Second) })
	if err != nil || !s.Records[0].Maintenance.Blocked || s.Records[0].Maintenance.NotBefore != at.Add(providerretry.MaxProviderWait).Format(time.RFC3339) {
		t.Fatal("bad hint shortened manual-review hold", err)
	}
}

func TestDNSMaintenanceCapacityWaitAndOldDeferCannotBypassPolicy(t *testing.T) {
	key, id, image, at := blockedDNSFixture(t, false)
	m, _, _ := decode(key, id, image)
	pending, a, _, _, err := beginDNSOperationAt(key, id, image, m.Generation, 0, "maintenance", at)
	if err != nil {
		t.Fatal(err)
	}
	if out, _, _, err := deferStagingDNSAttemptAt(key, id, pending, a, providerretry.Hint{}, at); err == nil || out != nil {
		t.Fatal("operator lease changed ordinary retry state")
	}
	p, _ := openDNSPlan(key, id, m)
	reserve, _ := dnsTotalReserve(key, id, m, p)
	full := fillArchiveHistory(t, key, id, image, maxHistory-reserve)
	_, g, _ := ReadStagingDNSPlan(key, id, full)
	if out, a, _, _, err := beginDNSOperationAt(key, id, full, g, 0, "maintenance", at); err == nil || out != nil || a != nil {
		t.Fatal("maintenance stole reserved completion space")
	}
	for _, duration := range []time.Duration{time.Hour, 3 * 24 * time.Hour} {
		intent, a, _, _, err := beginDNSOperationAt(key, id, image, m.Generation, 0, "maintenance", at)
		if err != nil {
			t.Fatal(err)
		}
		next, s, g, err := executeStagingDNSAttemptAt(key, id, intent, a, func() bool { return true }, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
			return dnsrecord.State{}, &providerretry.Failure{Hint: providerretry.Hint{NotBefore: at.Add(duration)}}
		}, func() time.Time { return at.Add(time.Second) })
		want := at.Add(max(24*time.Hour, duration)).Format(time.RFC3339)
		if err != nil || s.Records[0].Maintenance.NotBefore != want {
			t.Fatal("finite wait shortened", err)
		}
		nm, _, _ := decode(key, id, next)
		np, _ := openDNSPlan(key, id, nm)
		np.Records[0].Maintenance.Attempts = maxDNSMaintenance
		capped, _, _, err := sealDNSPlan(key, id, nm, np, "acme-dns-maintenance-result")
		if err != nil {
			t.Fatal(err)
		}
		if out, a, _, _, err := beginDNSOperationAt(key, id, capped, g+1, 0, "maintenance", mustDNSTime(want)); err == nil || out != nil || a != nil {
			t.Fatal("maintenance counter overflow/reset")
		}
	}
}
