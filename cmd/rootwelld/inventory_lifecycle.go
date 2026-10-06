package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"runtime"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func (g *gate) lifecycleEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	wanted := http.MethodGet
	if r.URL.Path == "/api/inventory/comparison-source" {
		wanted = http.MethodPost
	}
	if r.Method != wanted {
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
	if r.Header.Get("X-Rootwell-Request") != "1" || r.Header.Get("Sec-Fetch-Site") == "cross-site" || (wanted == http.MethodPost && !g.sameOrigin(r)) {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if wanted == http.MethodGet {
		events, generation, err := instanceaccess.ReadInventoryHistory(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
		if err != nil {
			inventoryError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			Schema     string                 `json:"schema_version"`
			Generation uint64                 `json:"generation"`
			Events     []inventorystore.Event `json:"events"`
			Monitoring monitorObservation     `json:"monitoring"`
		}{"rootwell.inventory.activity.v1", generation, events, g.monitorSnapshot(g.now(), generation)})
		return
	}
	var selection struct {
		Fingerprint string `json:"fingerprint"`
		Generation  uint64 `json:"expected_generation"`
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || media != "application/json" || readErr != nil || json.Unmarshal(body, &selection) != nil {
		http.Error(w, "invalid selection", http.StatusBadRequest)
		return
	}
	// Canonical selection rejects unknown/duplicate fields, unsafe numbers and
	// reordered representations; the first-party UI emits this exact shape.
	canonical, _ := json.Marshal(selection)
	if !bytes.Equal(canonical, body) || !publicinventory.ValidFingerprint(selection.Fingerprint) || selection.Generation < 1 || selection.Generation > 9007199254740991 {
		http.Error(w, "invalid selection", http.StatusBadRequest)
		return
	}
	records, generation, err := instanceaccess.ReadInventory(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
	if err != nil {
		inventoryError(w, err)
		return
	}
	if generation != selection.Generation {
		http.Error(w, "inventory changed; refresh first", http.StatusConflict)
		return
	}
	for _, record := range records {
		if record.Fingerprint == selection.Fingerprint {
			_ = json.NewEncoder(w).Encode(struct {
				Schema      string `json:"schema_version"`
				Fingerprint string `json:"fingerprint"`
				Generation  uint64 `json:"generation"`
				DER         []byte `json:"der"`
			}{"rootwell.inventory.comparison-source.v1", record.Fingerprint, generation, record.DER})
			return
		}
	}
	http.Error(w, "certificate no longer saved; refresh first", http.StatusConflict)
}
