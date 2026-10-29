package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"io"
	"mime"
	"net/http"
	"runtime"
	"time"
	"unicode/utf8"
)

type historyArchiveInput struct {
	Expected uint64
	Password string
}

func readHistoryArchiveInput(w http.ResponseWriter, r *http.Request, write bool) (historyArchiveInput, bool) {
	return readStorageArchiveInput(w, r, write, "lossless-history-archive")
}

func readStorageArchiveInput(w http.ResponseWriter, r *http.Request, write bool, requiredScope string) (historyArchiveInput, bool) {
	bad := func() (historyArchiveInput, bool) { return historyArchiveInput{}, false }
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
		return bad()
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	defer clear(body)
	if err != nil || !utf8.Valid(body) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(body))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return bad()
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		tok, err = d.Token()
		name, ok := tok.(string)
		if err != nil || !ok || fields[name] != nil {
			return bad()
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return bad()
		}
		fields[name] = value
	}
	tok, err = d.Token()
	if err != nil || tok != json.Delim('}') {
		return bad()
	}
	if _, err = d.Token(); err != io.EOF {
		return bad()
	}
	if !write {
		return historyArchiveInput{}, len(fields) == 0
	}
	if len(fields) != 5 {
		return bad()
	}
	for _, name := range []string{"expected_generation", "password", "confirm", "backup_confirmed", "scope"} {
		if fields[name] == nil {
			return bad()
		}
	}
	var input historyArchiveInput
	var password, scope *string
	var confirm, backup bool
	if json.Unmarshal(fields["expected_generation"], &input.Expected) != nil || input.Expected < 1 || input.Expected > 1000000 || json.Unmarshal(fields["password"], &password) != nil || password == nil || len(*password) < 1 || len(*password) > 256 || json.Unmarshal(fields["scope"], &scope) != nil || scope == nil || *scope != requiredScope || json.Unmarshal(fields["confirm"], &confirm) != nil || !confirm || json.Unmarshal(fields["backup_confirmed"], &backup) != nil || !backup {
		return bad()
	}
	input.Password = *password
	return input, true
}

func (g *gate) historyArchiveEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	g.storageArchiveEndpoint(w, r, s, signedIn, false)
}

func (g *gate) requestArchiveEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	g.storageArchiveEndpoint(w, r, s, signedIn, true)
}

func (g *gate) storageArchiveEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool, requests bool) {
	defer clear(s.dataKey[:])
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !signedIn {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if s.setup || !g.sameOrigin(r) || r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	if r.RemoteAddr != "" {
		c := http.NewResponseController(w)
		if c.SetReadDeadline(time.Now().Add(5*time.Second)) != nil || c.SetWriteDeadline(time.Now().Add(30*time.Second)) != nil {
			http.Error(w, "bounded request unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	write := r.URL.Path == "/api/inventory/history/archive"
	scope, schema := "lossless-history-archive", "rootwell.history-archive.v1"
	if requests {
		write = r.URL.Path == "/api/acme/request-storage/archive"
		scope, schema = "lossless-request-archive", "rootwell.request-archive.v1"
	}
	input, ok := readStorageArchiveInput(w, r, write, scope)
	defer func() { input.Password = "" }()
	if !ok {
		http.Error(w, "invalid archive request", http.StatusBadRequest)
		return
	}
	if runtime.GOOS != "linux" || !s.inventoryReady {
		http.Error(w, "Initialize encrypted storage and recovery in Linux Rootwell first.", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	started := time.Now()
	permit := func() bool {
		current, ready := g.currentSession(r)
		defer clear(current.dataKey[:])
		return ready && !current.setup && current.revision == s.revision && ctx.Err() == nil && !time.Now().Before(started)
	}
	if !permit() {
		http.Error(w, "session unavailable", http.StatusUnauthorized)
		return
	}
	if !g.startDerivation() {
		http.Error(w, "another password or key check is running", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-g.derive }()
	if write {
		if !g.allowAttempt() {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		setup, err := instanceaccess.Authenticate(g.accessPath, input.Password)
		input.Password = ""
		if err != nil || setup {
			http.Error(w, "authentication not accepted", http.StatusUnauthorized)
			return
		}
	}
	var saved any
	var err error
	if requests {
		saved, err = instanceaccess.InventoryRequestArchive(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Expected, permit)
	} else {
		saved, err = instanceaccess.InventoryHistoryArchive(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Expected, permit)
	}
	if err != nil {
		inventoryError(w, err)
		return
	}
	if !permit() {
		http.Error(w, "Result not confirmed. Read archive status before another action.", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		Schema      string `json:"schema_version"`
		CheckedAt   string `json:"checked_at"`
		NetworkUsed bool   `json:"network_used"`
		Saved       bool   `json:"saved"`
		Status      any    `json:"status"`
	}{schema, time.Now().UTC().Format(time.RFC3339), false, write, saved})
}
