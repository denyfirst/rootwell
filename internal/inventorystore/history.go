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
	case "import", "owner-changed", "location-added", "location-renamed", "location-removed", "record-deleted", "key-added":
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
	if len(m.History) > maxHistory {
		return nil, ErrInvalid
	}
	result := make([]Event, 0, len(m.History))
	var previous uint64
	for _, sealed := range m.History {
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
