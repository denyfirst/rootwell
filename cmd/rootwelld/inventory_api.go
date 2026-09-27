package main

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"runtime"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

const maxInventoryRequest = 22 << 20 // base64-wrapped maximum 16 MiB public input

type inventoryInput struct {
	Certificate []byte
	Owner       string
	Location    string
}

type inventoryItem struct {
	Fingerprint      string   `json:"fingerprint"`
	Subject          string   `json:"subject"`
	Issuer           string   `json:"issuer"`
	DNSNames         []string `json:"dns_names"`
	NotBefore        string   `json:"not_before"`
	NotAfter         string   `json:"not_after"`
	Owner            string   `json:"owner"`
	Location         string   `json:"location"`
	ImportGeneration uint64   `json:"import_generation"`
	ImportedAt       string   `json:"imported_at,omitempty"`
}

type inventoryOutput struct {
	Generation   uint64          `json:"generation"`
	Records      []inventoryItem `json:"records"`
	Verification string          `json:"verification"`
	Backup       string          `json:"backup"`
}

func (g *gate) inventoryEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !signedIn {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if s.setup {
		http.Error(w, "change the setup password first", http.StatusForbidden)
		return
	}
	if runtime.GOOS != "linux" {
		http.Error(w, "durable inventory is not supported on this platform", http.StatusNotImplemented)
		return
	}
	if !s.inventoryReady {
		http.Error(w, "installation identity is not enrolled", http.StatusConflict)
		return
	}
	if r.Method == http.MethodGet {
		if r.Header.Get("X-Rootwell-Request") != "1" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "request origin refused", http.StatusForbidden)
			return
		}
		records, generation, err := instanceaccess.ReadInventory(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
		if err != nil {
			inventoryError(w, err)
			return
		}
		writeInventoryJSON(w, http.StatusOK, records, generation)
		return
	}
	if !g.sameOrigin(r) {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	input, ok := readInventoryInput(w, r)
	if !ok {
		return
	}
	added, generation, err := instanceaccess.AppendInventory(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Certificate, input.Owner, input.Location)
	if err != nil {
		inventoryError(w, err)
		return
	}
	writeInventoryJSON(w, http.StatusCreated, added, generation)
}

func readInventoryInput(w http.ResponseWriter, r *http.Request) (inventoryInput, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return inventoryInput{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxInventoryRequest)
	d := json.NewDecoder(r.Body)
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryInput{}, false
	}
	var input inventoryInput
	seen := make(map[string]bool, 3)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryInput{}, false
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryInput{}, false
		}
		seen[name] = true
		switch name {
		case "certificate":
			err = d.Decode(&input.Certificate)
		case "owner":
			err = d.Decode(&input.Owner)
		case "location":
			err = d.Decode(&input.Location)
		default:
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryInput{}, false
		}
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryInput{}, false
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryInput{}, false
	}
	if _, err := d.Token(); err != io.EOF || len(input.Certificate) == 0 || len(input.Certificate) > 16<<20 {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryInput{}, false
	}
	return input, true
}

func inventoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, instanceaccess.ErrInventoryMissing):
		http.Error(w, "inventory not initialized; run the offline inventory-init ceremony", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrDuplicate):
		http.Error(w, "certificate is already saved", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrCapacity):
		http.Error(w, "inventory capacity reached", http.StatusConflict)
	case errors.Is(err, inventorystore.ErrLimit):
		http.Error(w, "inventory write limit reached; no further save is safe", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrLabel), errors.Is(err, publicinventory.ErrCertSize):
		http.Error(w, "invalid owner/location or certificate size", http.StatusBadRequest)
	case errors.Is(err, instanceaccess.ErrStaleUpgrade):
		http.Error(w, "installation changed; sign in again", http.StatusConflict)
	case errors.Is(err, instanceaccess.ErrAccessBusy):
		http.Error(w, "another inventory change is running; retry later", http.StatusServiceUnavailable)
	case errors.Is(err, instanceaccess.ErrInventoryUncertain):
		http.Error(w, "save outcome uncertain; reload inventory before another import", http.StatusServiceUnavailable)
	case errors.Is(err, inventorystore.ErrInvalid), errors.Is(err, instanceaccess.ErrInvalidFullSnapshot), errors.Is(err, instanceaccess.ErrUnsafeAccessStore):
		http.Error(w, "encrypted inventory unavailable; inspect storage before retrying", http.StatusServiceUnavailable)
	default:
		http.Error(w, "public certificate inventory operation refused", http.StatusBadRequest)
	}
}

func writeInventoryJSON(w http.ResponseWriter, status int, records []publicinventory.Record, generation uint64) {
	items := make([]inventoryItem, 0, len(records))
	for _, r := range records {
		items = append(items, inventoryItem{Fingerprint: r.Fingerprint, Subject: r.Subject, Issuer: r.Issuer, DNSNames: append([]string{}, r.DNSNames...),
			NotBefore: r.NotBefore, NotAfter: r.NotAfter, Owner: r.Owner, Location: r.Location, ImportGeneration: r.ImportGeneration, ImportedAt: r.ImportedAt})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(inventoryOutput{Generation: generation, Records: items, Verification: "not-performed",
		Backup: "Export a new full inventory snapshot after changes; backup is not automatic."})
}
