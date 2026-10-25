package main

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type automationStatusOutput struct {
	Schema           string `json:"schema_version"`
	Provider         string `json:"provider"`
	NetworkUsed      bool   `json:"network_used"`
	AutomaticRenewal bool   `json:"automatic_renewal"`
	UnlockExpires    string `json:"unlock_expires"`
	inventorystore.AutomationStatus
}

func (g *gate) automationStatusEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
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
	if _, ok := readAccountInput(w, r, false); !ok {
		http.Error(w, "invalid status request", http.StatusBadRequest)
		return
	}
	if runtime.GOOS != "linux" {
		http.Error(w, "Saved automation status requires Linux or Linux Docker.", http.StatusServiceUnavailable)
		return
	}
	if !s.inventoryReady {
		http.Error(w, "Initialize encrypted storage and full recovery first.", http.StatusConflict)
		return
	}
	if !g.startDerivation() {
		http.Error(w, "another key or password check is running", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-g.derive }()
	at := g.now().UTC().Truncate(time.Second)
	status, err := instanceaccess.ReadAutomationStatus(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, at)
	if err != nil {
		inventoryError(w, err)
		return
	}
	current, ready := g.currentSession(r)
	defer clear(current.dataKey[:])
	after := g.now()
	if !ready || current.setup || current.revision != s.revision || r.Context().Err() != nil || after.Before(at) || after.Sub(at) >= 10*time.Second {
		http.Error(w, "session or snapshot no longer available", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(automationStatusOutput{Schema: "rootwell.automation.status.v1", Provider: acmeplan.Provider,
		UnlockExpires: s.expires.UTC().Format(time.RFC3339), AutomationStatus: status})
}
