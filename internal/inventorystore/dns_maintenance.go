package inventorystore

import (
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

const maxDNSMaintenance = 65535

type dnsMaintenanceState struct {
	Attempts  int    `json:"attempts"`
	LastAt    string `json:"last_at"`
	NotBefore string `json:"not_before"`
	OutcomeAt string `json:"outcome_at"`
	Blocked   bool   `json:"blocked"`
	Resolved  bool   `json:"resolved"`
}
type DNSMaintenanceStatus struct {
	Attempts  int    `json:"attempts"`
	NotBefore string `json:"not_before"`
	Blocked   bool   `json:"blocked"`
}

func maintenanceState(r dnsPlanRecord, cleanup bool) *dnsMaintenanceState {
	if cleanup {
		return r.CleanupMaintenance
	}
	return r.Maintenance
}
func maintenanceResolved(r dnsPlanRecord, cleanup bool) bool {
	m := maintenanceState(r, cleanup)
	return m != nil && m.Resolved && m.OutcomeAt != "" && r.CheckedAt >= m.LastAt
}

// Normal/recovery policy authority is never reset. A new operator-only read
// grant is available only after the existing phase has reached a terminal state.
func maintenanceFloor(r dnsPlanRecord, cleanup bool) (string, bool, bool) {
	prior, blocked, recovery := r.Retry, r.Blocked, r.Recovery
	if cleanup {
		if r.Cleanup == nil {
			return "", false, false
		}
		prior, blocked, recovery = *r.Cleanup, r.CleanupBlocked, r.CleanupRecovery
	}
	terminal := blocked || prior.Attempts == providerretry.MaxAttempts && recovery != nil && (recovery.Blocked || recovery.Retry.Attempts == providerretry.MaxAttempts)
	if !terminal {
		return "", false, false
	}
	last, wait := prior.LastAt, prior.NotBefore
	if recovery != nil {
		last = max(last, recovery.Retry.LastAt)
		wait = max(wait, recovery.Retry.NotBefore)
		blocked = blocked || recovery.Blocked
	}
	delay := 24 * time.Hour
	if blocked {
		delay = providerretry.MaxProviderWait
	}
	floor := mustDNSTime(last).Add(delay)
	if floor.Year() > 2100 {
		return "", false, blocked
	}
	return max(wait, floor.Format(time.RFC3339)), true, blocked
}

func publicDNSMaintenance(r dnsPlanRecord) *DNSMaintenanceStatus {
	if r.State != "creating" && r.State != "deleting" {
		return nil
	}
	cleanup := r.State == "deleting"
	floor, ok, blocked := maintenanceFloor(r, cleanup)
	if !ok {
		return nil
	}
	s := &DNSMaintenanceStatus{NotBefore: floor, Blocked: blocked}
	if m := maintenanceState(r, cleanup); m != nil {
		s.Attempts = m.Attempts
		s.NotBefore = max(s.NotBefore, m.NotBefore)
		s.Blocked = m.Blocked
	}
	return s
}

func validDNSMaintenance(r dnsPlanRecord) bool {
	for phase, m := range []*dnsMaintenanceState{r.Maintenance, r.CleanupMaintenance} {
		if m == nil {
			continue
		}
		cleanup := phase == 1
		floor, terminal, _ := maintenanceFloor(r, cleanup)
		if !terminal || m.Attempts < 1 || m.Attempts > maxDNSMaintenance || !acmeorder.Time(m.LastAt) || !acmeorder.Time(m.NotBefore) || m.LastAt < floor || mustDNSTime(m.LastAt).Year() > 2100 || mustDNSTime(m.NotBefore).Year() > 2100 {
			return false
		}
		gap := mustDNSTime(m.NotBefore).Sub(mustDNSTime(m.LastAt))
		if gap < 24*time.Hour || gap > providerretry.MaxProviderWait || m.Blocked && gap < providerretry.MaxProviderWait {
			return false
		}
		if m.OutcomeAt != "" && (!acmeorder.Time(m.OutcomeAt) || m.OutcomeAt < m.LastAt || mustDNSTime(m.OutcomeAt).Year() > 2100) {
			return false
		}
		pending := r.State == "creating" && !cleanup || r.State == "deleting" && cleanup
		if m.Resolved {
			if pending || m.Blocked || m.OutcomeAt == "" || r.CheckedAt < m.OutcomeAt || cleanup && r.State != "deleted" || !cleanup && r.State != "created" && r.State != "deleting" && r.State != "deleted" {
				return false
			}
		} else if !pending || m.OutcomeAt != r.OutcomeAt {
			return false
		}
	}
	return true
}

func beginDNSMaintenance(r *dnsPlanRecord, at time.Time) error {
	cleanup := r.State == "deleting"
	if r.State != "creating" && !cleanup {
		return ErrInvalid
	}
	s := publicDNSMaintenance(*r)
	if s == nil || s.Attempts >= maxDNSMaintenance || at.Year() < 2020 || at.Year() > 2100 {
		return ErrInvalid
	}
	now := at.UTC().Truncate(time.Second)
	if now.Before(mustDNSTime(s.NotBefore)) || now.Format(time.RFC3339) < max(r.OutcomeAt, r.CheckedAt) {
		return ErrInvalid
	}
	next := now.Add(24 * time.Hour)
	if next.Year() > 2100 {
		return ErrInvalid
	}
	m := &dnsMaintenanceState{Attempts: s.Attempts + 1, LastAt: now.Format(time.RFC3339), NotBefore: next.Format(time.RFC3339)}
	if cleanup {
		r.CleanupMaintenance = m
	} else {
		r.Maintenance = m
	}
	r.OutcomeAt = ""
	return nil
}

func deferDNSMaintenance(m *dnsMaintenanceState, h providerretry.Hint, at time.Time) {
	last := mustDNSTime(m.LastAt)
	bound := h.NotBefore.UTC()
	if bound.Nanosecond() != 0 {
		bound = bound.Truncate(time.Second).Add(time.Second)
	}
	if h.Blocked || !h.NotBefore.IsZero() && (bound.Year() < 2020 || bound.Year() > 2100 || bound.Sub(last) > providerretry.MaxProviderWait) {
		m.Blocked = true
		m.NotBefore = last.Add(providerretry.MaxProviderWait).Format(time.RFC3339)
	} else if !h.NotBefore.IsZero() {
		m.NotBefore = max(m.NotBefore, bound.Format(time.RFC3339))
	}
	m.OutcomeAt = at.UTC().Format(time.RFC3339)
}
