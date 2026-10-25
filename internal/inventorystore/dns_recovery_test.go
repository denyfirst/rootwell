package inventorystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

func exhaustedDNSFixture(t *testing.T, cleanup bool) ([]byte, []byte, []byte, time.Time) {
	t.Helper()
	key, id, image := preparedDNSPlanFixture(t)
	at := time.Now().UTC().Truncate(time.Second)
	if cleanup {
		image, _, _ = dnsRunAt(t, key, id, image, 0, "add", at, dnsSuccessfulCreate(t))
		at = at.Add(2 * time.Second)
	}
	for n := 1; n <= 6; n++ {
		mode := "check"
		if n == 1 {
			mode = "add"
			if cleanup {
				mode = "cleanup"
			}
		}
		var s DNSPlanStatus
		image, s, _ = dnsRunAt(t, key, id, image, 0, mode, at, func(_ func() bool, _ []byte, _ dnsrecord.Scope, saved dnsrecord.State, c, read bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
			if n == 1 {
				intent := dnsrecord.State{State: "creating"}
				if cleanup {
					intent = dnsrecord.State{State: "deleting", ID: dnsOwnedID}
				}
				if err := checkpoint(intent); err != nil {
					t.Fatal(err)
				}
				return dnsrecord.State{}, errors.New("synthetic-lost-response")
			}
			if !read || c != cleanup {
				t.Fatal("ordinary check gained write")
			}
			return saved, nil
		})
		wait := s.Records[0].NotBefore
		if cleanup {
			wait = s.Records[0].CleanupNotBefore
		}
		at = mustDNSTime(wait)
	}
	return key, id, image, at
}

func runRecoveryAt(t *testing.T, key, id, image []byte, at time.Time, use DNSOperation) ([]byte, DNSPlanStatus, uint64) {
	t.Helper()
	_, g, err := ReadStagingDNSPlan(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	next, a, _, _, err := beginDNSOperationAt(key, id, image, g, 0, "recover", at)
	if err != nil {
		t.Fatal("recovery begin", err)
	}
	next, s, g, err := executeStagingDNSAttemptAt(key, id, next, a, func() bool { return true }, use, func() time.Time { return at.Add(time.Second) })
	if err != nil {
		t.Fatal("recovery result", err)
	}
	return next, s, g
}

func TestDNSRecoveryExactReadOnlyCreationAndCleanup(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "cleanup"}[cleanup], func(t *testing.T) {
			key, id, image, _ := exhaustedDNSFixture(t, cleanup)
			before, _, _ := decode(key, id, image)
			old, _ := openDNSPlan(key, id, before)
			at := mustDNSTime(old.Expires).Add(time.Second)
			result, s, g := runRecoveryAt(t, key, id, image, at, func(permit func() bool, token []byte, scope dnsrecord.Scope, saved dnsrecord.State, c, read bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
				if !permit() || string(token) != configToken || scope.Owner != old.Records[0].Owner || scope.Value != old.Records[0].Value || !read || c != cleanup {
					t.Fatal("recovery widened scope")
				}
				if err := checkpoint(saved); err == nil {
					t.Fatal("recovery authorized mutation")
				}
				if cleanup {
					if saved != (dnsrecord.State{State: "deleting", ID: dnsOwnedID}) {
						t.Fatal("owned deletion changed")
					}
					return dnsrecord.State{State: "deleted"}, nil
				}
				if saved != (dnsrecord.State{State: "creating"}) {
					t.Fatal("create replay")
				}
				return dnsrecord.State{State: "created", ID: dnsOwnedID}, nil
			})
			want := "created"
			if cleanup {
				want = "deleted"
			}
			if s.Records[0].State != want || s.Records[0].Attempts != old.Records[0].Retry.Attempts || cleanup && s.Records[0].CleanupAttempts != 6 || s.Records[0].Recovery != nil {
				t.Fatal("recovery reset counters or wrong state")
			}
			history, _, err := History(key, id, result)
			if err != nil || history[len(history)-2].Action != "acme-dns-recovery-started" || history[len(history)-1].Action != "acme-dns-recovery-result" {
				t.Fatal("missing recovery evidence")
			}
			for _, mode := range []string{"recover", "check", "add"} {
				if out, a, _, _, err := beginDNSOperationAt(key, id, result, g, 0, mode, at.Add(time.Hour)); err == nil || out != nil || a != nil {
					t.Fatal("terminal recovery replayed")
				}
			}
		})
	}
}

func TestDNSRecoveryLeaseAndEncryptedValidation(t *testing.T) {
	key, id, image, at := exhaustedDNSFixture(t, false)
	_, g, _ := ReadStagingDNSPlan(key, id, image)
	pending, a, _, _, err := beginDNSOperationAt(key, id, image, g, 0, "recover", at)
	if err != nil {
		t.Fatal(err)
	}
	copyLease := *a
	allowed := true
	out, _, _, err := executeStagingDNSAttemptAt(key, id, pending, a, func() bool { return allowed }, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
		allowed = false
		return dnsrecord.State{State: "created", ID: dnsOwnedID}, nil
	}, func() time.Time { return at.Add(time.Second) })
	if err == nil || out != nil {
		t.Fatal("revoked recovery published result")
	}
	if out, _, _, err := ExecuteStagingDNSAttempt(key, id, pending, &copyLease, func() bool { return true }, dnsSuccessfulCreate(t)); err == nil || out != nil {
		t.Fatal("recovery copied lease replayed")
	}
	for _, mutate := range []func(*dnsPlanRecord){
		func(r *dnsPlanRecord) { r.Recovery.Retry.Attempts = 0 },
		func(r *dnsPlanRecord) { r.Recovery.Retry.Attempts = 7 },
		func(r *dnsPlanRecord) { r.Retry.Attempts = 5 },
		func(r *dnsPlanRecord) { r.Blocked = true },
		func(r *dnsPlanRecord) { r.Recovery.Retry.LastAt = "2026-02-30T00:00:00Z" },
		func(r *dnsPlanRecord) {
			r.State = "borrowed"
			r.CheckedAt = r.Recovery.Retry.LastAt
			r.OutcomeAt = r.CheckedAt
		},
		func(r *dnsPlanRecord) { r.CleanupRecovery = r.Recovery; r.Recovery = nil },
	} {
		m, _, err := decode(key, id, pending)
		if err != nil {
			t.Fatal(err)
		}
		p, err := openDNSPlan(key, id, m)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&p.Records[0])
		plain, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		k, err := dnsPlanKey(key, id)
		if err != nil {
			t.Fatal(err)
		}
		item := m.DNSPlans[0]
		item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
		clear(k)
		clear(plain)
		if err != nil {
			t.Fatal(err)
		}
		m.DNSPlans = []sealedRecord{item}
		candidate, err := encode(key, m)
		if err != nil {
			t.Fatal(err)
		}
		if s, g, err := ReadStagingDNSPlan(key, id, candidate); err == nil || s.Prepared || g != 0 {
			t.Fatal("malformed encrypted recovery exposed state")
		}
	}
}

func TestDNSRecoveryDurableWaitExhaustionAndCapacity(t *testing.T) {
	key, id, image, at := exhaustedDNSFixture(t, true)
	// Admission requires twelve additional intent/outcome slots, not a reset
	// that spends the last reserved unresolved slot. Old image remains valid.
	m, _, _ := decode(key, id, image)
	m.Generation = maxGeneration - 1
	m.History = nil
	limited, err := encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(key, id, limited); err != nil {
		t.Fatal("older valid image refused", err)
	}
	if out, a, _, _, err := beginDNSOperationAt(key, id, limited, m.Generation, 0, "recover", at); !errors.Is(err, ErrLimit) || out != nil || a != nil {
		t.Fatal("recovery spent protected capacity")
	}
	m.Generation = maxGeneration - 13
	image, err = encode(key, m)
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 6; n++ {
		oldImage := bytes.Clone(image)
		var s DNSPlanStatus
		var g uint64
		image, s, g = runRecoveryAt(t, key, id, image, at, func(_ func() bool, _ []byte, _ dnsrecord.Scope, saved dnsrecord.State, c, read bool, _ func(dnsrecord.State) error) (dnsrecord.State, error) {
			if !c || !read {
				t.Fatal("cleanup recovery gained DELETE")
			}
			if n == 1 {
				return dnsrecord.State{}, &providerretry.Failure{Hint: providerretry.Hint{NotBefore: at.Add(time.Hour)}}
			}
			return saved, nil
		})
		row := s.Records[0]
		if row.State != "deleting" || row.CleanupAttempts != 6 || row.Recovery == nil || row.Recovery.Attempts != n {
			t.Fatal("recovery budget lost")
		}
		if n > 1 {
			old, _, _ := decode(key, id, oldImage)
			current, _, _ := decode(key, id, image)
			if len(image)+dnsReservedBytes(key, id, current) > len(oldImage)+dnsReservedBytes(key, id, old) {
				t.Fatal("reserved bytes do not fund recovery")
			}
		}
		if out, a, _, _, err := beginDNSOperationAt(key, id, image, g, 0, "recover", at); err == nil || out != nil || a != nil {
			t.Fatal("recovery skipped persisted wait")
		}
		at = mustDNSTime(row.Recovery.NotBefore)
	}
	_, g, _ := ReadStagingDNSPlan(key, id, image)
	if out, a, _, _, err := beginDNSOperationAt(key, id, image, g, 0, "recover", at); err == nil || out != nil || a != nil {
		t.Fatal("recovery budget reset")
	}
	if s, _, err := ReadNewStagingRequest(key, id, image); err != nil || s.Reason != "dns-cleanup-needed" {
		t.Fatal("unknown ownership abandoned")
	}
}

func TestDNSRecoveryRefusalAndMalformedResults(t *testing.T) {
	key, id, image, at := exhaustedDNSFixture(t, false)
	_, g, _ := ReadStagingDNSPlan(key, id, image)
	for _, when := range []time.Time{at.Add(-time.Second), at.Add(-time.Hour)} {
		if out, a, _, _, err := beginDNSOperationAt(key, id, image, g, 0, "recover", when); err == nil || out != nil || a != nil {
			t.Fatal("early recovery authorized")
		}
	}
	for _, result := range []dnsrecord.State{{State: "borrowed"}, {State: "new"}, {State: "deleted"}, {State: "created", ID: "foreign"}} {
		pending, a, _, _, err := beginDNSOperationAt(key, id, image, g, 0, "recover", at)
		if err != nil {
			t.Fatal(err)
		}
		out, _, _, err := executeStagingDNSAttemptAt(key, id, pending, a, func() bool { return true }, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
			return result, nil
		}, func() time.Time { return at.Add(time.Second) })
		if err == nil || out != nil {
			t.Fatal("invalid recovery verdict accepted")
		}
	}
	blocked, s, g := runRecoveryAt(t, key, id, image, at, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
		return dnsrecord.State{}, &providerretry.Failure{Hint: providerretry.Hint{Blocked: true}}
	})
	if s.Records[0].Recovery == nil || !s.Records[0].Recovery.Blocked {
		t.Fatal("bad hint not blocked")
	}
	if out, a, _, _, err := beginDNSOperationAt(key, id, blocked, g, 0, "recover", at.Add(8*24*time.Hour)); err == nil || out != nil || a != nil {
		t.Fatal("blocked recovery reset")
	}
}

func TestDNSRecoveryCannotOverrideOrdinaryProviderBlock(t *testing.T) {
	key, id, image, at := exhaustedDNSFixture(t, false)
	m, _, err := decode(key, id, image)
	if err != nil {
		t.Fatal(err)
	}
	p, err := openDNSPlan(key, id, m)
	if err != nil {
		t.Fatal(err)
	}
	p.Records[0].Blocked = true
	blocked, _, g, err := sealDNSPlan(key, id, m, p, "acme-dns-wait-saved")
	if err != nil {
		t.Fatal(err)
	}
	if out, a, _, _, err := beginDNSOperationAt(key, id, blocked, g, 0, "recover", at.Add(8*24*time.Hour)); err == nil || out != nil || a != nil {
		t.Fatal("read-only recovery bypassed an invalid provider hint")
	}
}
