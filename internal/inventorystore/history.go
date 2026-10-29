package inventorystore

import (
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"time"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

const maxHistory = 1024

// Event omits notes, DER and credentials. It is not independent audit evidence.
type Event struct {
	Generation   uint64   `json:"generation"`
	At           string   `json:"at"`
	Action       string   `json:"action"`
	Fingerprints []string `json:"fingerprints"`
}

func History(key, id, image []byte) ([]Event, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, 0, err
	}
	events, err := openHistory(key, id, m)
	return events, m.Generation, err
}

func eventContext(id []byte, generation uint64) inventoryseal.Context {
	var install [16]byte
	copy(install[:], id)
	return inventoryseal.Context{InstallationID: install, RecordID: sha256.Sum256([]byte("rootwell.history.event.v1:" + strconv.FormatUint(generation, 10))), Generation: generation}
}

func addEvent(key []byte, m *manifest, action string, ids []string) error {
	if len(m.History) >= maxHistory {
		return ErrLimit
	}
	// Generic certificate/note writes cannot consume a pending account's last
	// completion slot. Finishing registration has already changed its state.
	status, err := accountStatus(key, m.InstallationID, *m)
	if err != nil {
		return err
	}
	if status.Registration == "registration-pending" && (len(m.History) >= maxHistory-1 || m.Generation >= maxGeneration) {
		return ErrLimit
	}
	order, err := openOrder(key, m.InstallationID, *m)
	if err != nil {
		return err
	}
	reserve := 0
	if order.State == "request-pending" {
		reserve = 2
	}
	if order.State == "order-known" || order.State == "validation-pending" {
		reserve = 1
	}
	if reserve > 0 && (len(m.History) >= maxHistory-reserve || m.Generation > maxGeneration-uint64(reserve)) {
		return ErrLimit
	}
	// Non-issued observations and ordinary writes cannot consume the reserved
	// final pair slot, record slot or nonce generation after irreversible intent.
	if pendingIssuance(key, m.InstallationID, *m) && (len(m.History) >= maxHistory-1 || m.Generation >= maxGeneration || len(m.Records) >= maxRecords) {
		return ErrLimit
	}
	dns, err := openDNSPlan(key, m.InstallationID, *m)
	if err != nil {
		return err
	}
	total, err := dnsTotalReserve(key, m.InstallationID, *m, dns)
	if err != nil {
		return err
	}
	if total < 0 || total > 256 {
		return ErrLimit
	}
	if total > 0 && (len(m.History) >= maxHistory-total || m.Generation > maxGeneration-uint64(total)) {
		return ErrLimit
	}
	event := Event{Generation: m.Generation, At: time.Now().UTC().Format("2006-01-02T15:04:05Z"), Action: action, Fingerprints: ids}
	if !validEvent(event) {
		return ErrInvalid
	}
	plain, err := json.Marshal(event)
	if err != nil {
		return ErrInvalid
	}
	defer clear(plain)
	ciphertext, err := inventoryseal.Seal(key, eventContext(m.InstallationID, m.Generation), plain)
	if err != nil {
		return err
	}
	m.History = append(m.History, sealedRecord{Generation: m.Generation, Ciphertext: ciphertext})
	return nil
}

func validEvent(event Event) bool {
	if event.Generation < 2 || event.Generation > maxGeneration || len(event.Fingerprints) < 1 || len(event.Fingerprints) > 64 {
		return false
	}
	switch event.Action {
	case "acme-timing-read-started", "acme-timing-observed", "acme-timing-wait-saved", "acme-timing-interrupted":
	case "acme-dns-plan-prepared", "acme-dns-attempt-started", "acme-dns-wait-saved", "acme-dns-result-saved":
	case "acme-dns-recovery-started", "acme-dns-recovery-wait", "acme-dns-recovery-result":
	case "acme-dns-maintenance-started", "acme-dns-maintenance-wait", "acme-dns-maintenance-result":
	case "history-archived", "acme-request-history-archived":
	case "dns-cloudflare-saved", "dns-cloudflare-removed":
	case "import", "owner-changed", "location-added", "location-renamed", "location-removed", "record-deleted", "key-added", "acme-key-prepared", "acme-registration-started", "acme-account-registered", "acme-account-absent", "acme-order-started", "acme-order-located", "acme-dns-prepared", "acme-dns-acknowledged", "acme-validation-started", "acme-validation-observed", "acme-certificate-key-prepared", "acme-issuance-started", "acme-issuance-observed", "acme-certificate-saved", "acme-request-closed", "acme-renewal-started":
	default:
		return false
	}
	if event.Action != "import" && len(event.Fingerprints) != 1 {
		return false
	}
	parsed, err := time.Parse(time.RFC3339, event.At)
	if err != nil || parsed.UTC().Format("2006-01-02T15:04:05Z") != event.At {
		return false
	}
	seen := map[string]bool{}
	for _, id := range event.Fingerprints {
		if !publicinventory.ValidFingerprint(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func openHistory(key, id []byte, m manifest) ([]Event, error) {
	if len(m.History) > maxHistory || len(m.HistoryArchives) > maxHistoryArchives || len(m.HistoryArchives) > 0 && len(m.History) == 0 {
		return nil, ErrInvalid
	}
	if len(m.HistoryArchives) == 0 && m.HistoryArchiveStart != 0 || len(m.HistoryArchives) > 0 && (len(m.HistoryArchives[0]) == 0 || m.HistoryArchiveStart < 2 || m.HistoryArchives[0][0].Generation != m.HistoryArchiveStart) {
		return nil, ErrInvalid
	}
	sealedEvents := make([]sealedRecord, 0, len(m.History))
	for _, page := range m.HistoryArchives {
		if len(page) < minArchiveEvents || len(page) > maxHistory {
			return nil, ErrInvalid
		}
		sealedEvents = append(sealedEvents, page...)
	}
	sealedEvents = append(sealedEvents, m.History...)
	result := make([]Event, 0, len(sealedEvents))
	var previous uint64
	for _, sealed := range sealedEvents {
		if len(sealed.ID) != 0 || sealed.Generation < 2 || sealed.Generation > m.Generation || (previous != 0 && sealed.Generation != previous+1) {
			return nil, ErrInvalid
		}
		plain, err := inventoryseal.Open(key, eventContext(id, sealed.Generation), sealed.Ciphertext)
		if err != nil {
			return nil, ErrInvalid
		}
		var event Event
		valid := strictJSON(plain, &event) && validEvent(event) && event.Generation == sealed.Generation
		clear(plain)
		if !valid {
			return nil, ErrInvalid
		}
		result = append(result, event)
		previous = sealed.Generation
	}
	if len(result) > 0 && previous != m.Generation {
		return nil, ErrInvalid
	}
	return result, nil
}

func historyIDs(records []publicinventory.Record) []string {
	ids := make([]string, 0, len(records))
	for _, r := range records {
		ids = append(ids, r.Fingerprint)
	}
	return ids
}
