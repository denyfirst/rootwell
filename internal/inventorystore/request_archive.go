package inventorystore

import "time"

const maxClosedRequestArchives = 4
const minClosedRequestArchive = 16

type RequestArchiveStatus struct {
	Generation uint64 `json:"generation"`
	Active     int    `json:"active_requests"`
	Archived   int    `json:"archived_requests"`
	PagesFree  int    `json:"pages_free"`
	CanArchive bool   `json:"can_archive"`
	Reason     string `json:"reason"`
}

func closedRequestCount(m manifest) int {
	return len(m.ClosedRequests) + m.ClosedRequestArchiveCount
}

// Callers authenticate the complete image first. Order remains chronological;
// page boundaries never hide a duplicate URL, renewal anchor or tombstone.
func allClosedRequests(m manifest) []sealedRecord {
	items := make([]sealedRecord, 0, closedRequestCount(m))
	for _, page := range m.ClosedRequestArchives {
		items = append(items, page...)
	}
	return append(items, m.ClosedRequests...)
}

func requestArchiveStatus(m manifest) RequestArchiveStatus {
	s := RequestArchiveStatus{Generation: m.Generation, Active: len(m.ClosedRequests), Archived: m.ClosedRequestArchiveCount, PagesFree: maxClosedRequestArchives - len(m.ClosedRequestArchives), CanArchive: true, Reason: "ready"}
	switch {
	case s.Active < minClosedRequestArchive:
		s.CanArchive, s.Reason = false, "not-needed"
	case s.PagesFree == 0:
		s.CanArchive, s.Reason = false, "archive-limit"
	case m.Generation >= maxGeneration:
		s.CanArchive, s.Reason = false, "generation-limit"
	}
	return s
}

func ReadRequestArchive(key, id, image []byte) (RequestArchiveStatus, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return RequestArchiveStatus{}, err
	}
	return requestArchiveStatus(m), nil
}

// ArchiveClosedRequests moves only already closed encrypted records. It cannot
// discard uncertainty, reset limits, free bytes or grant historical authority.
func ArchiveClosedRequests(key, id, image []byte, expected uint64) ([]byte, RequestArchiveStatus, error) {
	return archiveClosedRequestsAt(key, id, image, expected, time.Now().UTC())
}

func archiveClosedRequestsAt(key, id, image []byte, expected uint64, now time.Time) ([]byte, RequestArchiveStatus, error) {
	bad := func(err error) ([]byte, RequestArchiveStatus, error) { return nil, RequestArchiveStatus{}, err }
	m, _, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	if expected == 0 || expected != m.Generation {
		return bad(ErrStaleGeneration)
	}
	if !requestArchiveStatus(m).CanArchive {
		return bad(ErrLimit)
	}
	now = now.UTC()
	if now.Year() < 2020 || now.Year() > 2100 {
		return bad(ErrInvalid)
	}
	stamp := now.Format(time.RFC3339)
	events, err := openHistory(key, id, m)
	if err != nil {
		return bad(err)
	}
	for _, event := range events {
		if event.At > stamp {
			return bad(ErrInvalid)
		}
	}
	fingerprint, err := closedArchiveMetadata(key, id, m, stamp)
	if err != nil {
		return bad(err)
	}
	m.ClosedRequestArchives = append(m.ClosedRequestArchives, m.ClosedRequests)
	m.ClosedRequestArchiveCount += len(m.ClosedRequests)
	m.ClosedRequests = nil
	m.Generation++
	if err := addEvent(key, &m, "acme-request-history-archived", []string{fingerprint}); err != nil {
		return bad(err)
	}
	next, err := encode(key, m)
	if err != nil {
		return bad(err)
	}
	s, err := ReadRequestArchive(key, id, next)
	if err != nil {
		return bad(err)
	}
	return next, s, nil
}
