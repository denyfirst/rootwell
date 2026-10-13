package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"runtime"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

const renewalSourceMarker = `<div id="acme-renewal-source" hidden></div>`

func (g *gate) renewalNavigationEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	defer clear(s.dataKey[:])
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !signedIn {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if s.setup || r.Header.Get("Origin") != "http://"+g.host || r.Header.Get("Sec-Fetch-Site") != "same-origin" || r.Header.Get("Sec-Fetch-Mode") != "navigate" || r.Header.Get("Sec-Fetch-Dest") != "document" {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	if runtime.GOOS != "linux" {
		http.Error(w, "Test renewal requires Linux or Linux Docker.", http.StatusServiceUnavailable)
		return
	}
	if !s.inventoryReady {
		http.Error(w, "Initialize the encrypted store and full recovery first.", http.StatusConflict)
		return
	}
	fp, expected, _, ok := readPublicNavigationSelection(w, r, true)
	if !ok {
		return
	}
	if !g.startDerivation() {
		http.Error(w, "another key or password check is running", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-g.derive }()
	source, gen, err := instanceaccess.ReadStagingRenewalSource(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, expected, fp)
	if err != nil {
		http.Error(w, "Refresh Certificates and select a saved Rootwell staging certificate with its matching key.", http.StatusConflict)
		return
	}
	current, ready := g.currentSession(r)
	defer clear(current.dataKey[:])
	if !ready || current.setup || current.revision != s.revision || r.Context().Err() != nil {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	body, err := authAssets.ReadFile("auth/acme.html")
	if err != nil || len(body) > 1<<20 || bytes.Count(body, []byte(renewalSourceMarker)) != 1 {
		http.Error(w, "automation unavailable", http.StatusServiceUnavailable)
		return
	}
	public, err := json.Marshal(struct {
		Schema     string `json:"schema_version"`
		Generation uint64 `json:"generation"`
		inventorystore.RenewalSource
	}{"rootwell.acme.renewal-selection.v1", gen, source})
	if err != nil || len(public) > 4096 {
		http.Error(w, "automation unavailable", http.StatusServiceUnavailable)
		return
	}
	body = bytes.Replace(body, []byte(renewalSourceMarker), []byte(`<div id="acme-renewal-source" hidden>`+string(public)+`</div>`), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body)
}
