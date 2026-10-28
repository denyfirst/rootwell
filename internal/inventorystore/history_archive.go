package inventorystore

import "time"

// A bounded extension of retained history, not deletion or nonce-generation
// recycling. Existing event ciphertext/context remains byte-for-byte identical.
const maxHistoryArchives = 4
const minArchiveEvents = 512

type HistoryArchiveStatus struct {
	Generation uint64 `json:"generation"`
	Active     int    `json:"active_events"`
	Archived   int    `json:"archived_events"`
	PagesFree  int    `json:"pages_free"`
	CanArchive bool   `json:"can_archive"`
	Reason     string `json:"reason"`
}

func archiveStatus(m manifest) HistoryArchiveStatus {
	s := HistoryArchiveStatus{Generation: m.Generation, Active: len(m.History), PagesFree: maxHistoryArchives - len(m.HistoryArchives), Reason: "ready", CanArchive: true}
	for _, page := range m.HistoryArchives {
		s.Archived += len(page)
	}
	switch {
	case len(m.History) < minArchiveEvents:
		s.CanArchive = false
		s.Reason = "not-needed"
	case s.PagesFree == 0:
		s.CanArchive = false
		s.Reason = "archive-limit"
	case m.Generation >= maxGeneration:
		s.CanArchive = false
		s.Reason = "generation-limit"
	}
	return s
}

func ReadHistoryArchive(key, id, image []byte) (HistoryArchiveStatus, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return HistoryArchiveStatus{}, err
	}
	return archiveStatus(m), nil
}

// ArchiveHistory repacks only already encrypted history. All certificate,
// account, DNS ownership/retry/wait, pending intent and reservation state stays
// unchanged. The existing exact writer admission still enforces byte/nonce
// limits. Moving events frees active slots; it does not free disk bytes.
func ArchiveHistory(key, id, image []byte, expected uint64) ([]byte, HistoryArchiveStatus, error) {
	bad := func(err error) ([]byte, HistoryArchiveStatus, error) { return nil, HistoryArchiveStatus{}, err }
	m, _, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	if expected == 0 || m.Generation != expected {
		return bad(ErrStaleGeneration)
	}
	if !archiveStatus(m).CanArchive {
		return bad(ErrLimit)
	}
	events, err := openHistory(key, id, m)
	if err != nil {
		return bad(err)
	}
	now := time.Now().UTC()
	if now.Year() < 2020 || now.Year() > 2100 {
		return bad(ErrInvalid)
	}
	for _, event := range events {
		if event.At > now.Format(time.RFC3339) {
			return bad(ErrInvalid)
		}
	}
	last := events[len(events)-1]
	if len(m.HistoryArchives) == 0 {
		m.HistoryArchiveStart = m.History[0].Generation
	}
	m.HistoryArchives = append(m.HistoryArchives, m.History)
	m.History = nil
	m.Generation++
	if err := addEvent(key, &m, "history-archived", []string{last.Fingerprints[0]}); err != nil {
		return bad(err)
	}
	next, err := encode(key, m)
	if err != nil {
		return bad(err)
	}
	// Authenticate the whole result; never publish a partially readable archive.
	s, err := ReadHistoryArchive(key, id, next)
	if err != nil {
		return bad(err)
	}
	return next, s, nil
}
