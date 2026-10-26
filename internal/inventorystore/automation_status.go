package inventorystore

import (
	"slices"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

// AutomationStatus is a single authenticated, read-only snapshot. Headroom is
// not an admission promise: each writer must repeat its own exact reservation.
// No secret, provider record ID, TXT, owner marker, note or internal URI escapes.
type AutomationStatus struct {
	Generation   uint64          `json:"generation"`
	CheckedAt    string          `json:"checked_at"`
	Request      string          `json:"request"`
	DNS          string          `json:"dns"`
	DNSWaitUntil string          `json:"dns_wait_until"`
	AccountReady bool            `json:"account_ready"`
	DNSSaved     bool            `json:"dns_saved"`
	Capacity     AutomationSpace `json:"capacity"`
	Certificates []RenewalReview `json:"certificates"`
}

type AutomationSpace struct {
	EventsFree      int    `json:"events_free"`
	EventsReserved  int    `json:"events_reserved"`
	ArchivesFree    int    `json:"archives_free"`
	RecordsFree     int    `json:"records_free"`
	GenerationsFree uint64 `json:"generations_free"`
	BytesFree       int    `json:"bytes_free"`
}

// ReviewAt is a local lifetime-based reminder, NOT a CA ARI recommendation,
// scheduler consent, renewal attempt, trust verdict or rate-limit exemption.
type RenewalReview struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	NotAfter    string `json:"not_after"`
	ReviewAt    string `json:"review_at"`
	State       string `json:"state"`
}

func ReadAutomationStatus(key, id, image []byte, at time.Time) (AutomationStatus, error) {
	bad := func(err error) (AutomationStatus, error) { return AutomationStatus{}, err }
	m, records, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	at = at.UTC().Truncate(time.Second)
	if at.Year() < 2020 || at.Year() > 2100 {
		return bad(ErrInvalid)
	}
	now := at.Format(time.RFC3339)
	// Authenticated timestamps establish a floor, not a trusted host clock.
	events, err := openHistory(key, id, m)
	if err != nil {
		return bad(err)
	}
	for _, event := range events {
		if now < event.At {
			return bad(ErrInvalid)
		}
	}
	account, err := accountStatus(key, id, m)
	if err != nil {
		return bad(err)
	}
	dns, err := openDNSPlan(key, id, m)
	if err != nil {
		return bad(err)
	}
	reserve, err := dnsTotalReserve(key, id, m, dns)
	if err != nil {
		return bad(err)
	}
	// dnsTotalReserve includes independent slots only while DNS is unresolved.
	if dnsPlanReserve(dns) == 0 {
		order, err := openOrder(key, id, m)
		if err != nil {
			return bad(err)
		}
		if account.Registration == "registration-pending" {
			reserve++
		}
		if order.State == "request-pending" {
			reserve += 2
		}
		if order.State == "order-known" || order.State == "validation-pending" {
			reserve++
		}
		if pendingIssuance(key, id, m) {
			reserve++
		}
	}
	if reserve < 0 || reserve > 256 {
		return bad(ErrInvalid)
	}
	space := AutomationSpace{
		EventsFree: max(0, maxHistory-len(m.History)-reserve), EventsReserved: reserve,
		ArchivesFree: maxClosedRequests - len(m.ClosedRequests), RecordsFree: maxRecords - len(records),
		GenerationsFree: maxGeneration - m.Generation, BytesFree: max(0, maxImage-len(image)-reservedImageBytes(key, id, m)),
	}
	if space.GenerationsFree >= uint64(reserve) {
		space.GenerationsFree -= uint64(reserve)
	} else {
		space.GenerationsFree = 0
	}
	next, err := newRequestStatus(key, id, m, now)
	if err != nil || next.Reason == "clock-unavailable" {
		return bad(ErrInvalid)
	}
	request := "active"
	switch next.Reason {
	case "not-started":
		request = "none"
	case "complete", "expired":
		request = "close-needed"
	case "unknown-order":
		request = "unknown"
	case "capacity":
		request = "capacity"
	}
	s := AutomationStatus{Generation: m.Generation, CheckedAt: now, Request: request,
		DNS: "none", AccountReady: account.Registration == "registered", DNSSaved: len(m.CloudflareConfigs) == 1,
		Capacity: space, Certificates: []RenewalReview{}}
	s.DNS, s.DNSWaitUntil = dnsAutomationState(dns, now)
	// Completed successors prevent a retained original pair from becoming a
	// second automatic renewal candidate. Deleted successors still count: deleting
	// a pair is not permission to restart an older lineage.
	superseded, err := completedRenewalSources(key, id, m)
	if err != nil {
		return bad(err)
	}
	for _, r := range records {
		row := RenewalReview{Fingerprint: r.Fingerprint, Name: "Saved certificate · " + r.Fingerprint[:17], NotAfter: r.NotAfter, State: "manual"}
		if len(r.DNSNames) > 0 {
			if names, ok := acmeorder.Names([]string{r.DNSNames[0]}); ok {
				row.Name = names[0]
			}
		}
		if r.StagingOrigin != nil && r.HasPrivateKey && r.KeyStatus == "matched" {
			// decode already authenticated the record/completion/material linkage;
			// do not reopen every archive separately for every saved certificate.
			start, e1 := time.Parse(time.RFC3339, r.NotBefore)
			end, e2 := time.Parse(time.RFC3339, r.NotAfter)
			if e1 != nil || e2 != nil || !end.After(start) {
				return bad(ErrInvalid)
			}
			// Unix seconds avoid time.Duration saturation for long-lived fixtures.
			// Validity is not assumed to be 90 days. Parsed RFC3339 years fit int64.
			lifetime := end.Unix() - start.Unix()
			offset := lifetime * 2 / 3
			if lifetime < 10*24*60*60 {
				offset = lifetime / 2
			}
			review := time.Unix(start.Unix()+offset, 0).UTC()
			row.ReviewAt, row.State = review.Format(time.RFC3339), "waiting"
			switch {
			case superseded[r.Fingerprint]:
				row.State = "superseded"
			case !at.Before(end):
				row.State = "expired"
			case at.Before(start):
				row.State = "not-yet-valid"
			case !at.Before(review):
				row.State = "due"
			}
		}
		s.Certificates = append(s.Certificates, row)
	}
	slices.SortFunc(s.Certificates, func(a, b RenewalReview) int {
		if a.NotAfter < b.NotAfter {
			return -1
		}
		if a.NotAfter > b.NotAfter {
			return 1
		}
		if a.Fingerprint < b.Fingerprint {
			return -1
		}
		if a.Fingerprint > b.Fingerprint {
			return 1
		}
		return 0
	})
	return s, nil
}

func dnsAutomationState(p dnsPlanPayload, now string) (string, string) {
	state, wait := "none", ""
	for _, r := range p.Records {
		// A bad clock is never represented as a harmless wait.
		if now < max(p.PreparedAt, r.CheckedAt, r.OutcomeAt, r.Retry.LastAt) || r.Cleanup != nil && now < r.Cleanup.LastAt || r.Recovery != nil && now < r.Recovery.Retry.LastAt || r.CleanupRecovery != nil && now < r.CleanupRecovery.Retry.LastAt {
			return "clock-unavailable", ""
		}
		if r.State == "creating" || r.State == "deleting" {
			retry, blocked, recovery := r.Retry, r.Blocked, r.Recovery
			if r.State == "deleting" {
				retry, blocked, recovery = *r.Cleanup, r.CleanupBlocked, r.CleanupRecovery
			}
			if blocked || recovery != nil && (recovery.Blocked || recovery.Retry.Attempts >= providerretry.MaxAttempts) {
				return "maintenance", ""
			}
			if recovery != nil {
				retry = recovery.Retry
			}
			if retry.NotBefore > now {
				wait = max(wait, retry.NotBefore)
			}
			state = "unknown"
		} else if r.State == "created" && state != "unknown" {
			state = "cleanup-needed"
		}
	}
	return state, wait
}
