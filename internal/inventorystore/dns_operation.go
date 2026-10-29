package inventorystore

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

func validDNSPlanRecord(r dnsPlanRecord, prepared string, historical bool) bool {
	if !validDNSMaintenance(r) {
		return false
	}
	for phase, recovery := range []*dnsRecoveryState{r.Recovery, r.CleanupRecovery} {
		if recovery == nil {
			continue
		}
		prior := r.Retry
		if phase == 1 {
			if r.Cleanup == nil || r.State != "deleting" && r.State != "deleted" {
				return false
			}
			prior = *r.Cleanup
		}
		if r.State == "new" || r.State == "borrowed" || !providerretry.Valid(recovery.Retry) || recovery.Retry.Attempts < 1 || prior.Attempts != providerretry.MaxAttempts || recovery.Retry.LastAt < prior.NotBefore || phase == 0 && r.Blocked || phase == 1 && r.CleanupBlocked {
			return false
		}
		pending := phase == 0 && r.State == "creating" || phase == 1 && r.State == "deleting"
		if !pending && (recovery.Blocked && !maintenanceResolved(r, phase == 1) || r.CheckedAt < recovery.Retry.LastAt) {
			return false
		}
	}
	last := r.Retry.LastAt
	if r.Cleanup != nil {
		last = r.Cleanup.LastAt
	}
	if r.Recovery != nil {
		last = max(last, r.Recovery.Retry.LastAt)
	}
	if r.CleanupRecovery != nil {
		last = max(last, r.CleanupRecovery.Retry.LastAt)
	}
	for _, m := range []*dnsMaintenanceState{r.Maintenance, r.CleanupMaintenance} {
		if m != nil {
			last = max(last, m.LastAt)
		}
	}
	if r.OutcomeAt != "" && (!acmeorder.Time(r.OutcomeAt) || mustDNSTime(r.OutcomeAt).Year() > 2100 || r.OutcomeAt < last) {
		return false
	}
	if r.State == "new" {
		return r.Retry.Attempts == 0 && !r.Blocked && r.ID == "" && r.Cleanup == nil && !r.CleanupBlocked && r.CheckedAt == "" && r.OutcomeAt == ""
	}
	if r.Retry.Attempts < 1 || r.Retry.LastAt < prepared {
		return false
	}
	checked := acmeorder.Time(r.CheckedAt) && r.CheckedAt >= r.Retry.LastAt && mustDNSTime(r.CheckedAt).Year() <= 2100
	switch r.State {
	case "creating":
		return !historical && r.ID == "" && r.Cleanup == nil && !r.CleanupBlocked && r.CheckedAt == ""
	case "borrowed":
		return checked && r.OutcomeAt >= r.CheckedAt && !r.Blocked && r.ID == "" && r.Cleanup == nil && !r.CleanupBlocked
	case "created":
		return !historical && checked && r.OutcomeAt >= r.CheckedAt && (!r.Blocked || maintenanceResolved(r, false)) && dnsPlanHex(r.ID) && r.Cleanup == nil && !r.CleanupBlocked
	case "deleting", "deleted":
		if !checked || r.Blocked && !maintenanceResolved(r, false) || !dnsPlanHex(r.ID) || r.Cleanup == nil || !providerretry.Valid(*r.Cleanup) || r.Cleanup.Attempts < 1 || r.Cleanup.LastAt < r.Retry.LastAt || r.Cleanup.LastAt < prepared {
			return false
		}
		if r.State == "deleting" {
			return !historical && r.CheckedAt <= r.Cleanup.LastAt
		}
		return (!r.CleanupBlocked || maintenanceResolved(r, true)) && r.CheckedAt >= r.Cleanup.LastAt && r.OutcomeAt >= r.CheckedAt
	default:
		return false
	}
}

// DNSOperation is a trusted internal fixed-provider callback, not a public
// request contract. Token/scope live only for this synchronous invocation.
type DNSOperation func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error)

func BeginStagingDNSOperation(key, id, image []byte, expected uint64, index int, mode string) ([]byte, *DNSAttempt, DNSPlanStatus, uint64, error) {
	return beginDNSOperationAt(key, id, image, expected, index, mode, time.Now().UTC())
}

// Execute requires the exact durable intent image under the same writer lock.
// It consumes the lease before borrowing anything. No raw provider error leaves
// this boundary; failed I/O saves only the fixed pending state and bounded hint.
func ExecuteStagingDNSAttempt(key, id, image []byte, attempt *DNSAttempt, permit func() bool, use DNSOperation) ([]byte, DNSPlanStatus, uint64, error) {
	return executeStagingDNSAttemptAt(key, id, image, attempt, permit, use, time.Now)
}
func executeStagingDNSAttemptAt(key, id, image []byte, attempt *DNSAttempt, permit func() bool, use DNSOperation, clock func() time.Time) ([]byte, DNSPlanStatus, uint64, error) {
	bad := func(err error) ([]byte, DNSPlanStatus, uint64, error) { return nil, DNSPlanStatus{}, 0, err }
	if attempt == nil || attempt.lease == nil || !attempt.lease.used.CompareAndSwap(false, true) {
		return bad(ErrInvalid)
	}
	l := attempt.lease
	if l.imageHash != sha256.Sum256(image) {
		return bad(ErrStaleGeneration)
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	if m.historical || l.generation != m.Generation || permit == nil || use == nil {
		return bad(ErrInvalid)
	}
	p, err := openDNSPlan(key, id, m)
	if err != nil || l.index < 0 || l.index >= len(p.Records) {
		return bad(ErrInvalid)
	}
	r := &p.Records[l.index]
	prior := dnsrecord.State{State: "new"}
	retry := r.Retry
	if l.cleanup {
		if r.State != "deleting" || r.Cleanup == nil || !l.recovery && !l.maintenance && l.readOnly != (r.Cleanup.Attempts > 1) {
			return bad(ErrInvalid)
		}
		retry = *r.Cleanup
		prior = dnsrecord.State{State: "created", ID: r.ID}
		if l.readOnly {
			prior.State = "deleting"
		}
	} else {
		if r.State != "creating" || !l.recovery && !l.maintenance && l.readOnly != (r.Retry.Attempts > 1) {
			return bad(ErrInvalid)
		}
		if l.readOnly {
			prior.State = "creating"
		}
	}
	var recovery *dnsRecoveryState
	if l.recovery {
		recovery = r.Recovery
		if l.cleanup {
			recovery = r.CleanupRecovery
		}
		if !l.readOnly || retry.Attempts != providerretry.MaxAttempts || recovery == nil || recovery.Blocked {
			return bad(ErrInvalid)
		}
		retry = recovery.Retry
	}
	maintenance := maintenanceState(*r, l.cleanup)
	if l.maintenance {
		if !l.readOnly || l.recovery || maintenance == nil || maintenance.Resolved || maintenance.OutcomeAt != "" || r.OutcomeAt != "" {
			return bad(ErrInvalid)
		}
		retry.LastAt = maintenance.LastAt
	}
	order, err := openOrder(key, id, m)
	if err != nil {
		return bad(err)
	}
	allowed := func() bool {
		now := clock().UTC()
		stamp := now.Format("2006-01-02T15:04:05Z")
		return now.Year() >= 2020 && now.Year() <= 2100 && stamp >= retry.LastAt && permit() && (l.cleanup || l.readOnly || stamp < min(p.Expires, order.Expires))
	}
	if !allowed() {
		return bad(ErrInvalid)
	}
	config, err := openCloudflareConfig(key, id, m)
	defer clear(config.Token)
	if err != nil || len(config.Token) == 0 || p.ConfigGeneration != m.CloudflareConfigs[0].Generation {
		return bad(ErrInvalid)
	}
	scope := dnsrecord.Scope{ZoneID: p.ZoneID, ZoneName: p.ZoneName, Name: r.Name, Value: r.Value, Owner: r.Owner}
	checkpointed := false
	checkpoint := func(state dnsrecord.State) error {
		wanted := dnsrecord.State{State: "creating"}
		if l.cleanup {
			wanted = dnsrecord.State{State: "deleting", ID: r.ID}
		}
		if l.readOnly || checkpointed || state != wanted || !allowed() {
			return ErrInvalid
		}
		// This exact image's irreversible intent is already durably committed
		// by the writer. Never borrow this callback outside that transaction.
		checkpointed = true
		return nil
	}
	if !allowed() {
		return bad(ErrInvalid)
	}
	observed, callErr := use(allowed, config.Token, scope, prior, l.cleanup, l.readOnly, checkpoint)
	if !allowed() {
		return bad(ErrInvalid)
	}
	if callErr != nil {
		hint := providerretry.Hint{}
		var failure *providerretry.Failure
		if errors.As(callErr, &failure) && failure != nil {
			hint = failure.Hint
		}
		if l.maintenance {
			deferDNSMaintenance(maintenance, hint, clock().UTC())
			r.OutcomeAt = maintenance.OutcomeAt
			return sealDNSPlan(key, id, m, p, "acme-dns-maintenance-wait")
		}
		wait, waitErr := providerretry.Apply(retry, hint)
		if l.recovery {
			if waitErr != nil {
				recovery.Blocked = true
			} else {
				recovery.Retry = wait
			}
		} else if l.cleanup {
			if waitErr != nil {
				r.CleanupBlocked = true
			} else {
				r.Cleanup = &wait
			}
		} else {
			if waitErr != nil {
				r.Blocked = true
			} else {
				r.Retry = wait
			}
		}
		r.OutcomeAt = clock().UTC().Format("2006-01-02T15:04:05Z")
		action := "acme-dns-wait-saved"
		if l.recovery {
			action = "acme-dns-recovery-wait"
		}
		return sealDNSPlan(key, id, m, p, action)
	}
	if l.cleanup {
		if observed.ID != "" && observed.ID != r.ID {
			return bad(ErrInvalid)
		}
		if observed.State == "deleted" && observed.ID == "" {
			r.State = "deleted"
			r.CheckedAt = clock().UTC().Format("2006-01-02T15:04:05Z")
		} else if !(l.readOnly && observed == prior) {
			return bad(ErrInvalid)
		}
	} else {
		switch {
		case observed.State == "borrowed" && observed.ID == "" && !l.readOnly && !checkpointed:
			r.State = "borrowed"
			r.CheckedAt = clock().UTC().Format("2006-01-02T15:04:05Z")
		case observed.State == "created" && dnsPlanHex(observed.ID) && (l.readOnly || checkpointed):
			r.State = "created"
			r.ID = observed.ID
			r.CheckedAt = clock().UTC().Format("2006-01-02T15:04:05Z")
		case l.readOnly && observed == prior:
			// Complete empty listing is not proof a timed-out create cannot
			// appear later. Retain uncertainty and never fall back to POST.
		default:
			return bad(ErrInvalid)
		}
	}
	if !allowed() {
		return bad(ErrInvalid)
	}
	r.OutcomeAt = clock().UTC().Format("2006-01-02T15:04:05Z")
	if l.maintenance {
		maintenance.OutcomeAt = r.OutcomeAt
		maintenance.Resolved = r.State == "created" && !l.cleanup || r.State == "deleted" && l.cleanup
		if maintenance.Resolved {
			// Bind the receipt to the confirmed observation, not a potentially
			// later publication clock read crossing a second boundary.
			maintenance.OutcomeAt = r.CheckedAt
		}
	}
	action := "acme-dns-result-saved"
	if l.recovery {
		action = "acme-dns-recovery-result"
	}
	if l.maintenance {
		action = "acme-dns-maintenance-result"
	}
	return sealDNSPlan(key, id, m, p, action)
}
