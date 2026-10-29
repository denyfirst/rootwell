package inventorystore

import (
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

// RenewalCycle contains authenticated public metadata only. It conveys neither
// a key nor permission to execute. Every writer still checks the exact image.
type RenewalCycle struct {
	Generation       uint64              `json:"generation"`
	Fingerprint      string              `json:"fingerprint"`
	Name             string              `json:"name"`
	Domains          []string            `json:"domains"`
	ConfigGeneration uint64              `json:"config_generation"`
	Zone             string              `json:"zone"`
	AccountReady     bool                `json:"account_ready"`
	OtherPending     bool                `json:"other_pending"`
	Timing           RenewalTimingStatus `json:"timing"`
	OrderState       string              `json:"order_state"`
	OrderSource      string              `json:"order_source"`
	OrderExpires     string              `json:"order_expires"`
	RequiredDNS      bool                `json:"required_dns"`
	Close            NewRequestStatus    `json:"close"`
	KeyPrepared      bool                `json:"key_prepared"`
	Issuance         IssuanceStatus      `json:"issuance"`
	SavedFingerprint string              `json:"saved_fingerprint"`
	DNS              DNSPlanStatus       `json:"dns"`
	EventsLeft       int                 `json:"events_left"`
	GenerationsLeft  uint64              `json:"generations_left"`
	BytesLeft        int                 `json:"bytes_left"`
	RecordsLeft      int                 `json:"records_left"`
	ClosuresLeft     int                 `json:"closures_left"`
}

// ReadRenewalCycle never projects raw orders/archives, TXT values, provider IDs,
// token digests, notes, keys, CSR or DER. No clock override is a runtime API.
func ReadRenewalCycle(key, id, image []byte, expected uint64, fp string) (RenewalCycle, error) {
	return readRenewalCycleAt(key, id, image, expected, fp, time.Now().UTC())
}

func readRenewalCycleAt(key, id, image []byte, expected uint64, fp string, at time.Time) (RenewalCycle, error) {
	bad := func(err error) (RenewalCycle, error) { return RenewalCycle{}, err }
	m, records, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	if expected == 0 || expected != m.Generation {
		return bad(ErrStaleGeneration)
	}
	r, _, err := timingSource(records, fp)
	if err != nil {
		return bad(err)
	}
	source, err := renewalSource(key, id, m, fp)
	if err != nil {
		return bad(err)
	}
	timing, _, err := readTimingStatusAt(key, id, image, expected, fp, at)
	if err != nil {
		return bad(err)
	}
	// This also checks the history/clock floor before any partial projection.
	if _, err := ReadAutomationStatus(key, id, image, at); err != nil {
		return bad(err)
	}
	account, err := accountStatus(key, id, m)
	if err != nil {
		return bad(err)
	}
	config, err := cloudflarePublic(key, id, m)
	if err != nil {
		return bad(err)
	}
	order, err := openOrder(key, id, m)
	if err != nil {
		return bad(err)
	}
	issuance, err := openIssuance(key, id, m)
	if err != nil {
		return bad(err)
	}
	dns, err := openDNSPlan(key, id, m)
	if err != nil {
		return bad(err)
	}
	close, err := newRequestStatus(key, id, m, at.UTC().Format(time.RFC3339))
	if err != nil {
		return bad(err)
	}
	request, err := certificateRequestStatus(key, id, m)
	if err != nil {
		return bad(err)
	}
	other, err := timingReserve(key, id, m)
	if err != nil {
		return bad(err)
	}
	if timing.Pending {
		other--
	}
	s := RenewalCycle{Generation: m.Generation, Fingerprint: fp, Name: source.Domains[0], Domains: slices.Clone(source.Domains),
		AccountReady: account.Registration == "registered", Timing: timing,
		OrderState: order.State, OrderSource: order.RenewalSource, OrderExpires: order.Expires, Close: close,
		KeyPrepared: request.Prepared, Issuance: publicIssuance(issuance), DNS: publicDNSPlan(dns, order.Expires),
		EventsLeft: maxHistory - len(m.History), GenerationsLeft: maxGeneration - m.Generation, BytesLeft: maxImage - len(image),
		RecordsLeft: maxRecords - len(records), ClosuresLeft: maxClosedRequests - len(m.ClosedRequests)}
	s.OtherPending = other > 0
	if config.State == "saved" {
		s.ConfigGeneration, s.Zone = m.CloudflareConfigs[0].Generation, config.ZoneName
	}
	if issuance.Completion != nil && issuance.Completion.DeletedAt == "" {
		s.SavedFingerprint = issuance.Completion.Fingerprint
	}
	for _, row := range order.Records {
		s.RequiredDNS = s.RequiredDNS || row.Required
	}
	if !slices.Equal(source.Domains, r.DNSNames) || !acmeorder.CanonicalNames(source.Domains) {
		return bad(ErrInvalid)
	}
	return s, nil
}

const RenewalCycleEvents = 320
const RenewalCycleBytes = 4 << 20

// CycleDecision is a local action proposal, never a lease. Consumers must not
// accept it from the browser or persist it as restart/unlock authority.
type CycleDecision struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
	Next   string `json:"next"`
	Index  int    `json:"index"`
}

func cycleDecision(action, reason string) CycleDecision {
	return CycleDecision{Action: action, Reason: reason, Index: -1}
}

// DecideRenewalCycle uses only the current authenticated snapshot plus remaining
// runtime budget. Long provider waits win; recovery/maintenance never runs here.
func DecideRenewalCycle(s RenewalCycle, events, bytes int, at time.Time) CycleDecision {
	pause := func(reason string) CycleDecision { return cycleDecision("pause", reason) }
	choose := func(action string) CycleDecision { return cycleDecision(action, action) }
	if at.Year() < 2020 || at.Year() > 2100 || s.Generation == 0 || events < 1 || events > RenewalCycleEvents || bytes < 1 || bytes > RenewalCycleBytes {
		return pause("invalid-state")
	}
	if !publicinventory.ValidFingerprint(s.Fingerprint) || s.Timing.Fingerprint != s.Fingerprint || !acmeorder.CanonicalNames(s.Domains) {
		return pause("invalid-state")
	}
	if !s.AccountReady {
		return pause("account-unavailable")
	}
	if s.OtherPending {
		return pause("other-work-pending")
	}
	if s.ConfigGeneration == 0 || s.Zone == "" {
		return pause("dns-configuration")
	}
	for _, domain := range s.Domains {
		base := strings.TrimPrefix(domain, "*.")
		if base != s.Zone && !strings.HasSuffix(base, "."+s.Zone) {
			return pause("dns-zone-mismatch")
		}
	}
	bound := s.OrderSource == s.Fingerprint && s.OrderState != "not-started"
	saved := bound && s.SavedFingerprint != "" && s.Issuance.State == "certificate-saved"
	// Finished receipt cleanup may outlive the original/order validity and a CA
	// wait. It never requires a new CA call, key or replacement order.
	if !saved {
		if s.EventsLeft < events || s.GenerationsLeft < uint64(events) || s.BytesLeft < bytes || s.RecordsLeft < 1 {
			return pause("storage-capacity")
		}
		if !bound && (s.Timing.Expired || s.Timing.Superseded) {
			return pause("source-ended")
		}
		if s.Timing.Pending {
			return pause("timing-interrupted")
		}
		if s.Timing.Blocked {
			return pause("provider-maintenance")
		}
	}
	wait := func(stamp string) (CycleDecision, bool) {
		if stamp == "" {
			return CycleDecision{}, false
		}
		next, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil {
			return pause("clock-unavailable"), true
		}
		if at.Before(next) {
			d := choose("wait")
			d.Reason, d.Next = "provider-wait", stamp
			return d, true
		}
		return CycleDecision{}, false
	}
	if !bound {
		needed := 1
		if s.OrderState != "not-started" {
			needed++
		}
		if s.ClosuresLeft < needed {
			return pause("request-capacity")
		}
		if s.OrderState != "not-started" && !s.Close.Available {
			return pause("request-active")
		}
		for _, row := range s.DNS.Records {
			if row.State != "borrowed" && row.State != "deleted" {
				return pause("dns-cleanup")
			}
		}
		if d, ok := wait(s.Timing.ProviderNotBefore); ok {
			return d
		}
		if !s.Timing.Prepared {
			return choose("timing")
		}
		if s.Timing.State != "ari" && s.Timing.State != "unsupported" {
			return pause("timing-unconfirmed")
		}
		if s.Timing.EffectiveAt == "" {
			return pause("timing-unconfirmed")
		}
		if d, ok := wait(s.Timing.EffectiveAt); ok {
			if d.Action != "wait" {
				return d
			}
			if s.Timing.CanRead {
				return choose("timing")
			}
			if check, e := time.Parse(time.RFC3339Nano, s.Timing.NextCheck); e == nil && check.After(at) {
				due, _ := time.Parse(time.RFC3339Nano, d.Next)
				if check.Before(due) {
					d.Next = s.Timing.NextCheck
				}
			}
			d.Reason = "renewal-wait"
			return d
		}
		if s.OrderState != "not-started" {
			return choose("close")
		}
		return choose("order")
	}
	if !saved {
		if s.ClosuresLeft < 1 {
			return pause("request-capacity")
		}
		if s.Close.Reason == "expired" {
			return pause("request-expired")
		}
		for _, stamp := range []string{s.OrderExpires, s.Issuance.Expires} {
			if stamp != "" {
				until, err := time.Parse(time.RFC3339Nano, stamp)
				if err != nil {
					return pause("clock-unavailable")
				}
				if !at.Before(until) {
					return pause("request-expired")
				}
			}
		}
		if d, ok := wait(s.Timing.ProviderNotBefore); ok {
			return d
		}
		switch s.OrderState {
		case "request-pending":
			return pause("order-unconfirmed")
		case "order-known":
			return choose("order-read")
		case "validation-failed":
			return pause("validation-failed")
		case "dns-ready", "dns-acknowledged", "validation-pending", "validation-waiting", "domain-verified":
		default:
			return pause("invalid-state")
		}
		if s.RequiredDNS && !s.DNS.Prepared && (s.OrderState == "dns-ready" || s.OrderState == "dns-acknowledged") {
			return choose("dns-plan")
		}
	}
	var selected *CycleDecision
	var earliest time.Time
	for i, row := range s.DNS.Records {
		action, stamp, count, blocked := "", row.NotBefore, row.Attempts, row.Blocked
		if saved {
			stamp, count, blocked = row.CleanupNotBefore, row.CleanupAttempts, row.CleanupBlocked
			switch row.State {
			case "created":
				action = "dns-cleanup"
			case "deleting":
				action = "dns-check"
			case "borrowed", "deleted":
				continue
			default:
				return pause("dns-unconfirmed")
			}
		} else {
			switch row.State {
			case "new":
				if s.OrderState != "dns-ready" && s.OrderState != "dns-acknowledged" {
					return pause("dns-unconfirmed")
				}
				action = "dns-add"
			case "creating":
				action = "dns-check"
			case "created", "borrowed":
				continue
			default:
				return pause("dns-unconfirmed")
			}
		}
		if blocked || count >= 6 || row.Recovery != nil || row.Maintenance != nil {
			return pause("dns-maintenance")
		}
		if d, ok := wait(stamp); ok {
			if d.Action != "wait" {
				return d
			}
			next, _ := time.Parse(time.RFC3339Nano, d.Next)
			if earliest.IsZero() || next.Before(earliest) {
				earliest = next
			}
			continue
		}
		if selected == nil {
			d := choose(action)
			d.Index = i
			selected = &d
		}
	}
	if selected != nil {
		return *selected
	}
	if !earliest.IsZero() {
		d := choose("wait")
		d.Reason, d.Next = "dns-wait", timingStamp(earliest)
		return d
	}
	if saved {
		return choose("complete")
	}
	switch s.OrderState {
	case "dns-ready":
		return choose("ack")
	case "dns-acknowledged":
		return choose("validate")
	case "validation-pending", "validation-waiting":
		return choose("validation-read")
	case "domain-verified":
		if !s.KeyPrepared {
			return choose("key")
		}
		switch s.Issuance.State {
		case "not-started":
			return choose("certificate")
		case "issuance-pending", "not-issued", "awaiting-certificate":
			return choose("certificate-read")
		default:
			return pause("certificate-unconfirmed")
		}
	}
	return pause("invalid-state")
}
