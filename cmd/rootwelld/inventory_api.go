package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"runtime"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

const maxInventoryRequest = 22 << 20 // base64-wrapped maximum 16 MiB public input

// Native same-tab navigation accepts only identity, generation and destination,
// never certificate input. No Workbench network or browser-storage capability.
func (g *gate) inventoryWorkbenchEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.Method != http.MethodPost {
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
	// Native forms cannot set the JSON API header. Exact Origin AND browser
	// navigation metadata are mandatory here; absent metadata fails closed.
	if r.Header.Get("Origin") != "http://"+g.host || r.Header.Get("Sec-Fetch-Site") != "same-origin" ||
		r.Header.Get("Sec-Fetch-Mode") != "navigate" || r.Header.Get("Sec-Fetch-Dest") != "document" {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	fingerprint, generation, tool, ok := readWorkbenchSelection(w, r)
	if !ok {
		return
	}
	records, actual, err := instanceaccess.ReadInventory(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
	if err != nil {
		inventoryError(w, err)
		return
	}
	if actual != generation {
		http.Error(w, "inventory changed; return to Saved certificates and refresh", http.StatusConflict)
		return
	}
	for _, record := range records {
		if record.Fingerprint == fingerprint {
			g.writeInventoryWorkbench(w, record, tool)
			return
		}
	}
	http.Error(w, "certificate no longer saved; return to Saved certificates and refresh", http.StatusConflict)
}

func readWorkbenchSelection(w http.ResponseWriter, r *http.Request) (string, uint64, string, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		http.Error(w, "form body required", http.StatusUnsupportedMediaType)
		return "", 0, "", false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if r.ParseForm() != nil || len(r.PostForm) != 3 || len(r.PostForm["fingerprint"]) != 1 ||
		len(r.PostForm["expected_generation"]) != 1 || len(r.PostForm["tool"]) != 1 {
		http.Error(w, "invalid selection", http.StatusBadRequest)
		return "", 0, "", false
	}
	fingerprint, rawGeneration, tool := r.PostForm.Get("fingerprint"), r.PostForm.Get("expected_generation"), r.PostForm.Get("tool")
	generation, err := strconv.ParseUint(rawGeneration, 10, 64)
	validFingerprint := len(fingerprint) == 95
	for i, c := range fingerprint {
		if i%3 == 2 {
			validFingerprint = validFingerprint && c == ':'
		} else {
			validFingerprint = validFingerprint && (c >= '0' && c <= '9' || c >= 'A' && c <= 'F')
		}
	}
	if err != nil || generation == 0 || generation > 9007199254740991 || strconv.FormatUint(generation, 10) != rawGeneration ||
		!validFingerprint || (tool != "inspect" && tool != "verify") {
		http.Error(w, "invalid selection", http.StatusBadRequest)
		return "", 0, "", false
	}
	return fingerprint, generation, tool, true
}

const inventoryWorkbenchMarker = `<div id="inventory-source" hidden></div>`

func (g *gate) writeInventoryWorkbench(w http.ResponseWriter, record publicinventory.Record, tool string) {
	f, err := g.assets.Open("index.html")
	if err != nil {
		http.Error(w, "workbench unavailable", http.StatusServiceUnavailable)
		return
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(body) > 1<<20 || bytes.Count(body, []byte(inventoryWorkbenchMarker)) != 1 ||
		len(record.DER) == 0 || len(record.DER) > 64<<10 {
		http.Error(w, "workbench unavailable", http.StatusServiceUnavailable)
		return
	}
	// HTML-escaped JSON in inert text, never a script. No owner/location notes,
	// trust, credential or private-key fields. Browser reparses public identity.
	payload, err := json.Marshal(struct {
		Schema      string `json:"schema_version"`
		Fingerprint string `json:"fingerprint"`
		DER         []byte `json:"der"`
		Tool        string `json:"tool"`
	}{"rootwell.inventory.workbench.v1", record.Fingerprint, record.DER, tool})
	if err != nil {
		http.Error(w, "workbench unavailable", http.StatusServiceUnavailable)
		return
	}
	body = bytes.Replace(body, []byte(inventoryWorkbenchMarker), []byte(`<div id="inventory-source" hidden>`+string(payload)+`</div>`), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body)
}

type inventoryInput struct {
	Certificate []byte
	Owner       string
	Location    string
}

type inventoryLocationInput struct {
	Fingerprint        string
	Location           string
	ExpectedGeneration uint64
}

type inventoryOwnerInput struct {
	Fingerprint        string
	Owner              string
	ExpectedGeneration uint64
}

type inventoryLocationChangeInput struct {
	Fingerprint        string
	OldLocation        string
	NewLocation        string
	Action             inventorystore.LocationChange
	ExpectedGeneration uint64
}

type inventoryDeleteInput struct {
	Fingerprint        string
	TypedFingerprint   string
	Confirmation       string
	ExpectedGeneration uint64
}

type inventoryDeleteOutput struct {
	Fingerprint  string `json:"fingerprint"`
	Generation   uint64 `json:"generation"`
	Deleted      bool   `json:"deleted"`
	Verification string `json:"verification"`
	Backup       string `json:"backup"`
}

type inventoryItem struct {
	HasPrivateKey    bool                   `json:"has_private_key"`
	Fingerprint      string                 `json:"fingerprint"`
	Subject          string                 `json:"subject"`
	Issuer           string                 `json:"issuer"`
	DNSNames         []string               `json:"dns_names"`
	NotBefore        string                 `json:"not_before"`
	NotAfter         string                 `json:"not_after"`
	Owner            string                 `json:"owner"`
	Location         string                 `json:"location"`
	Locations        []string               `json:"locations"`
	ImportGeneration uint64                 `json:"import_generation"`
	ImportedAt       string                 `json:"imported_at,omitempty"`
	Expiry           publicinventory.Expiry `json:"expiry"`
}

func (g *gate) inventoryLocationEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.Method != http.MethodPost {
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
	if !g.sameOrigin(r) {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	input, ok := readInventoryLocationInput(w, r)
	if !ok {
		return
	}
	updated, generation, err := instanceaccess.AssociateInventoryLocation(g.accessPath, s.dataKey[:], s.installationID[:], s.revision,
		input.ExpectedGeneration, input.Fingerprint, input.Location)
	if err != nil {
		inventoryError(w, err)
		return
	}
	g.writeInventoryJSON(w, http.StatusOK, []publicinventory.Record{updated}, generation)
}

func readInventoryLocationInput(w http.ResponseWriter, r *http.Request) (inventoryLocationInput, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return inventoryLocationInput{}, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || len(body) == 0 || !utf8.Valid(body) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationInput{}, false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationInput{}, false
	}
	var input inventoryLocationInput
	seen := make(map[string]bool, 3)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationInput{}, false
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationInput{}, false
		}
		seen[name] = true
		switch name {
		case "fingerprint":
			err = d.Decode(&input.Fingerprint)
		case "location":
			err = d.Decode(&input.Location)
		case "expected_generation":
			err = d.Decode(&input.ExpectedGeneration)
		default:
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationInput{}, false
		}
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationInput{}, false
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationInput{}, false
	}
	if _, err := d.Token(); err != io.EOF || !seen["fingerprint"] || !seen["location"] || !seen["expected_generation"] ||
		len(input.Fingerprint) == 0 || len(input.Fingerprint) > 128 || input.Location == "" || input.ExpectedGeneration == 0 {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationInput{}, false
	}
	if publicinventory.ValidateLocation(input.Location) != nil {
		http.Error(w, "invalid location", http.StatusBadRequest)
		return inventoryLocationInput{}, false
	}
	return input, true
}

func (g *gate) inventoryLocationChangeEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.Method != http.MethodPost {
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
	if !g.sameOrigin(r) {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	input, ok := readInventoryLocationChangeInput(w, r)
	if !ok {
		return
	}
	updated, generation, err := instanceaccess.ChangeInventoryLocation(g.accessPath, s.dataKey[:], s.installationID[:], s.revision,
		input.ExpectedGeneration, input.Fingerprint, input.OldLocation, input.NewLocation, input.Action)
	if err != nil {
		inventoryError(w, err)
		return
	}
	g.writeInventoryJSON(w, http.StatusOK, []publicinventory.Record{updated}, generation)
}

func readInventoryLocationChangeInput(w http.ResponseWriter, r *http.Request) (inventoryLocationChangeInput, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return inventoryLocationChangeInput{}, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || len(body) == 0 || !utf8.Valid(body) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationChangeInput{}, false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationChangeInput{}, false
	}
	var input inventoryLocationChangeInput
	var action string
	seen := make(map[string]bool, 5)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationChangeInput{}, false
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationChangeInput{}, false
		}
		seen[name] = true
		switch name {
		case "fingerprint":
			err = d.Decode(&input.Fingerprint)
		case "old_location":
			err = d.Decode(&input.OldLocation)
		case "new_location":
			err = d.Decode(&input.NewLocation)
		case "action":
			err = d.Decode(&action)
		case "expected_generation":
			err = d.Decode(&input.ExpectedGeneration)
		default:
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationChangeInput{}, false
		}
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationChangeInput{}, false
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationChangeInput{}, false
	}
	if _, err := d.Token(); err != io.EOF || !seen["fingerprint"] || !seen["old_location"] || !seen["action"] || !seen["expected_generation"] ||
		len(input.Fingerprint) == 0 || len(input.Fingerprint) > 128 || input.ExpectedGeneration == 0 ||
		publicinventory.ValidateLocation(input.OldLocation) != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationChangeInput{}, false
	}
	switch action {
	case "rename":
		if !seen["new_location"] || publicinventory.ValidateLocation(input.NewLocation) != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationChangeInput{}, false
		}
		input.Action = inventorystore.LocationRename
	case "remove":
		if seen["new_location"] {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationChangeInput{}, false
		}
		input.Action = inventorystore.LocationRemove
	default:
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationChangeInput{}, false
	}
	return input, true
}

func (g *gate) inventoryOwnerEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.Method != http.MethodPost {
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
	if !g.sameOrigin(r) {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	input, ok := readInventoryOwnerInput(w, r)
	if !ok {
		return
	}
	updated, generation, err := instanceaccess.UpdateInventoryOwner(g.accessPath, s.dataKey[:], s.installationID[:], s.revision,
		input.ExpectedGeneration, input.Fingerprint, input.Owner)
	if err != nil {
		inventoryError(w, err)
		return
	}
	g.writeInventoryJSON(w, http.StatusOK, []publicinventory.Record{updated}, generation)
}

func readInventoryOwnerInput(w http.ResponseWriter, r *http.Request) (inventoryOwnerInput, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return inventoryOwnerInput{}, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || len(body) == 0 || !utf8.Valid(body) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryOwnerInput{}, false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryOwnerInput{}, false
	}
	var input inventoryOwnerInput
	seen := make(map[string]bool, 3)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryOwnerInput{}, false
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryOwnerInput{}, false
		}
		seen[name] = true
		switch name {
		case "fingerprint":
			err = d.Decode(&input.Fingerprint)
		case "owner":
			var raw json.RawMessage
			err = d.Decode(&raw)
			if err == nil {
				if len(raw) == 0 || raw[0] != '"' {
					http.Error(w, "invalid request body", http.StatusBadRequest)
					return inventoryOwnerInput{}, false
				}
				err = json.Unmarshal(raw, &input.Owner)
			}
		case "expected_generation":
			err = d.Decode(&input.ExpectedGeneration)
		default:
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryOwnerInput{}, false
		}
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryOwnerInput{}, false
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryOwnerInput{}, false
	}
	if _, err := d.Token(); err != io.EOF || !seen["fingerprint"] || !seen["owner"] || !seen["expected_generation"] ||
		len(input.Fingerprint) == 0 || len(input.Fingerprint) > 128 || input.ExpectedGeneration == 0 || !publicinventory.ValidOwner(input.Owner) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryOwnerInput{}, false
	}
	return input, true
}

func (g *gate) inventoryDeleteEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.Method != http.MethodPost {
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
	if !g.sameOrigin(r) {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	input, ok := readInventoryDeleteInput(w, r)
	if !ok {
		return
	}
	generation, err := instanceaccess.DeleteInventoryRecord(g.accessPath, s.dataKey[:], s.installationID[:], s.revision,
		input.ExpectedGeneration, input.Fingerprint)
	if err != nil {
		inventoryError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(inventoryDeleteOutput{Fingerprint: input.Fingerprint, Generation: generation, Deleted: true,
		Verification: "not-performed", Backup: "Create a new full snapshot after deletion. Older snapshots may restore the deleted record."})
}

func readInventoryDeleteInput(w http.ResponseWriter, r *http.Request) (inventoryDeleteInput, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return inventoryDeleteInput{}, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || len(body) == 0 || !utf8.Valid(body) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryDeleteInput{}, false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryDeleteInput{}, false
	}
	var input inventoryDeleteInput
	seen := make(map[string]bool, 4)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryDeleteInput{}, false
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryDeleteInput{}, false
		}
		seen[name] = true
		switch name {
		case "fingerprint":
			err = d.Decode(&input.Fingerprint)
		case "typed_fingerprint":
			err = d.Decode(&input.TypedFingerprint)
		case "confirmation":
			err = d.Decode(&input.Confirmation)
		case "expected_generation":
			err = d.Decode(&input.ExpectedGeneration)
		default:
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryDeleteInput{}, false
		}
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryDeleteInput{}, false
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryDeleteInput{}, false
	}
	if _, err := d.Token(); err != io.EOF || !seen["fingerprint"] || !seen["typed_fingerprint"] ||
		!seen["confirmation"] || !seen["expected_generation"] || len(input.Fingerprint) == 0 || len(input.Fingerprint) > 128 ||
		input.TypedFingerprint != input.Fingerprint || input.Confirmation != "delete-public-record" || input.ExpectedGeneration == 0 {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryDeleteInput{}, false
	}
	return input, true
}

type inventoryOutput struct {
	Generation   uint64              `json:"generation"`
	Records      []inventoryItem     `json:"records"`
	Verification string              `json:"verification"`
	Backup       string              `json:"backup"`
	Monitoring   inventoryMonitoring `json:"monitoring"`
}

type inventoryMonitoring struct {
	CheckedAt           string `json:"checked_at"`
	ClockSource         string `json:"clock_source"`
	RefreshAfterSeconds int    `json:"refresh_after_seconds"`
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
		g.writeInventoryJSON(w, http.StatusOK, records, generation)
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
	g.writeInventoryJSON(w, http.StatusCreated, added, generation)
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
	case errors.Is(err, publicinventory.ErrLocationDuplicate):
		http.Error(w, "location is already listed for this certificate", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrLocationCapacity):
		http.Error(w, "certificate location limit reached", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrLocationMissing):
		http.Error(w, "location is no longer listed; refresh first", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrLocationUnchanged):
		http.Error(w, "location is unchanged", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrOwnerUnchanged):
		http.Error(w, "owner is unchanged", http.StatusConflict)
	case errors.Is(err, inventorystore.ErrNotFound):
		http.Error(w, "certificate is no longer in the inventory; refresh first", http.StatusNotFound)
	case errors.Is(err, inventorystore.ErrStaleGeneration):
		http.Error(w, "inventory changed; refresh before changing metadata", http.StatusConflict)
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

func (g *gate) writeInventoryJSON(w http.ResponseWriter, status int, records []publicinventory.Record, generation uint64) {
	now := g.now().UTC().Truncate(time.Second)
	if now.Year() < 0 || now.Year() > 9999 {
		http.Error(w, "server clock unavailable; expiry was not calculated", http.StatusServiceUnavailable)
		return
	}
	items := make([]inventoryItem, 0, len(records))
	for _, r := range records {
		items = append(items, inventoryItem{Fingerprint: r.Fingerprint, Subject: r.Subject, Issuer: r.Issuer, DNSNames: append([]string{}, r.DNSNames...),
			NotBefore: r.NotBefore, NotAfter: r.NotAfter, Owner: r.Owner, Location: r.Location, Locations: append([]string{}, r.Locations...),
			ImportGeneration: r.ImportGeneration, ImportedAt: r.ImportedAt, HasPrivateKey: r.HasPrivateKey, Expiry: publicinventory.ObserveExpiry(r, now)})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(inventoryOutput{Generation: generation, Records: items, Verification: "not-performed",
		Monitoring: inventoryMonitoring{CheckedAt: now.Format("2006-01-02T15:04:05Z"), ClockSource: "server-clock", RefreshAfterSeconds: 60},
		Backup:     "Export a new full inventory snapshot after changes; backup is not automatic."})
}
