package inventorystore

import "time"

// TimingReadiness is local recovery guidance, not reset/prune/replay authority.
// Both projections come from the same authenticated image and exact generation.
type TimingReadiness struct {
	Generation uint64              `json:"generation"`
	Name       string              `json:"name"`
	Timing     RenewalTimingStatus `json:"timing"`
	CanStart   bool                `json:"can_start"`
	Reason     string              `json:"reason"`
	Recovery   string              `json:"recovery"`
	NextCheck  string              `json:"next_check"`
}

func ReadTimingReadiness(key, id, image []byte, expected uint64, fp string, at time.Time) (TimingReadiness, error) {
	s, g, err := readTimingStatusAt(key, id, image, expected, fp, at)
	if err != nil {
		return TimingReadiness{}, err
	}
	a, err := ReadAutomationStatus(key, id, image, at)
	if err != nil || a.Generation != g {
		return TimingReadiness{}, ErrInvalid
	}
	return timingReadiness(s, a, at), nil
}

func timingReadiness(s RenewalTimingStatus, a AutomationStatus, at time.Time) TimingReadiness {
	p := TimingReadiness{Generation: a.Generation, Timing: s, Reason: "ready", Recovery: "none"}
	for _, row := range a.Certificates {
		if row.Fingerprint == s.Fingerprint {
			p.Name = row.Name
			break
		}
	}
	deny := func(reason, recovery string) TimingReadiness { p.Reason = reason; p.Recovery = recovery; return p }
	if s.Pending {
		return deny("timing-interrupted", "timing")
	}
	if s.Blocked {
		return deny("provider-maintenance", "maintenance")
	}
	if s.Expired || s.Superseded {
		return deny("source-ended", "certificates")
	}
	if !a.AccountReady {
		return deny("account-unavailable", "request")
	}
	switch a.DNS {
	case "maintenance", "clock-unavailable":
		return deny("dns-maintenance", "maintenance")
	case "unknown":
		return deny("dns-unconfirmed", "dns")
	case "cleanup-needed":
		return deny("dns-cleanup", "dns")
	case "none":
	default:
		return deny("storage-unavailable", "maintenance")
	}
	if a.Request == "unknown" {
		return deny("request-unconfirmed", "request")
	}
	if a.Request == "active" {
		return deny("request-active", "request")
	}
	// A new check must not consume another operation's reserved outcome slots.
	if a.Request == "capacity" || a.Capacity.EventsFree < 2 || a.Capacity.GenerationsFree < 2 || a.Capacity.BytesFree < 2*timingOutcomeBytes {
		return deny("storage-capacity", "capacity")
	}
	var latest time.Time
	for _, stamp := range []string{s.NextCheck, s.ProviderNotBefore} {
		if stamp != "" {
			next, ok := timingTime(stamp)
			if !ok {
				return deny("clock-unavailable", "maintenance")
			}
			if next.After(at) && next.After(latest) {
				latest = next
				p.NextCheck = stamp
			}
		}
	}
	if p.NextCheck != "" {
		p.Reason = "provider-wait"
	}
	p.CanStart = true
	return p
}
