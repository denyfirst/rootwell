package main

import (
	"time"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

type monitorObservation struct {
	Status     string   `json:"status"`
	CheckedAt  string   `json:"checked_at,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	Generation uint64   `json:"generation,omitempty"`
	Attention  []string `json:"attention"`
}

// The worker retains no independent unlock key and extends no session lifetime.
func (g *gate) startMonitor() {
	g.monitorStop = make(chan struct{})
	g.monitorDone = make(chan struct{})
	go func() {
		defer close(g.monitorDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			g.tickMonitor(g.now())
			select {
			case <-g.monitorStop:
				return
			case <-ticker.C:
			}
		}
	}()
}

func (g *gate) setMonitor(observation monitorObservation) {
	g.monitorMu.Lock()
	g.monitor = observation
	g.monitorMu.Unlock()
}

func (g *gate) tickMonitor(now time.Time) {
	now = now.UTC().Truncate(time.Second)
	g.monitorMu.Lock()
	previous, _ := time.Parse(time.RFC3339, g.monitor.CheckedAt)
	g.monitorMu.Unlock()
	if now.Year() < 0 || now.Year() > 9999 || (!previous.IsZero() && now.Before(previous)) {
		g.setMonitor(monitorObservation{Status: "clock-unavailable", CheckedAt: previous.Format(time.RFC3339)})
		return
	}
	revision, err := instanceaccess.Revision(g.accessPath)
	if err != nil {
		g.mu.Lock()
		for id := range g.sessions {
			g.forgetSessionLocked(id)
		}
		g.mu.Unlock()
		g.setMonitor(monitorObservation{Status: "unavailable"})
		return
	}
	g.mu.Lock()
	var selected session
	var selectedID [32]byte
	found := false
	for id, s := range g.sessions {
		if s.revision != revision || !now.Before(s.expires) {
			g.forgetSessionLocked(id)
			continue
		}
		if !s.setup && s.inventoryReady && (!found || s.expires.After(selected.expires)) {
			selected, selectedID, found = s, id, true
		}
	}
	g.mu.Unlock()
	if !found {
		g.setMonitor(monitorObservation{Status: "locked"})
		return
	}
	defer func() { clear(selected.dataKey[:]) }()
	read := g.monitorRead
	if read == nil {
		read = func(s session) ([]publicinventory.Record, uint64, error) {
			return instanceaccess.ReadInventory(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
		}
	}
	records, generation, err := read(selected)
	if err != nil {
		g.setMonitor(monitorObservation{Status: "unavailable"})
		return
	}
	attention := []string{}
	for _, record := range records {
		expiry := publicinventory.ObserveExpiry(record, now)
		if expiry.Status == "invalid" || expiry.Status == "expired" || expiry.Status == "future" || (expiry.DaysLeft != nil && *expiry.DaysLeft <= 30) {
			attention = append(attention, record.Fingerprint)
		}
	}
	afterRevision, revisionErr := instanceaccess.Revision(g.accessPath)
	if revisionErr != nil || afterRevision != selected.revision {
		g.setMonitor(monitorObservation{Status: "unavailable"})
		return
	}
	// Publish while holding the session lock so a logout cannot publish a late
	// result. Reads already in progress can still finish; they grant no unlock.
	g.mu.Lock()
	defer g.mu.Unlock()
	current, exists := g.sessions[selectedID]
	if !exists || current.revision != selected.revision || !g.now().Before(current.expires) {
		g.setMonitor(monitorObservation{Status: "locked"})
		return
	}
	g.setMonitor(monitorObservation{Status: "ready", CheckedAt: now.Format(time.RFC3339), ExpiresAt: selected.expires.UTC().Format(time.RFC3339), Generation: generation, Attention: attention})
}

func (g *gate) monitorSnapshot(now time.Time, generation uint64) monitorObservation {
	g.monitorMu.Lock()
	result := g.monitor
	result.Attention = append([]string{}, result.Attention...)
	g.monitorMu.Unlock()
	if result.Status == "" {
		result.Status = "not-running"
	}
	if result.Status == "ready" {
		at, e1 := time.Parse(time.RFC3339, result.CheckedAt)
		end, e2 := time.Parse(time.RFC3339, result.ExpiresAt)
		if e1 != nil || e2 != nil || now.Before(at) || !now.Before(end) || now.Sub(at) >= 2*time.Minute || generation != result.Generation {
			return monitorObservation{Status: "stale", Attention: []string{}}
		}
	}
	return result
}
