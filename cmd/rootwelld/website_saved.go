package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

const savedWebsiteMarker = `<div id="website-saved-source" hidden></div>`

// This navigation reads one public snapshot. It has no target, key or network
// capability; the existing website API still needs separate explicit consent.
func (g *gate) savedWebsiteEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
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
		http.Error(w, "Saved certificates require Linux or Linux Docker.", http.StatusServiceUnavailable)
		return
	}
	if !s.inventoryReady {
		http.Error(w, "Initialize the encrypted store and full recovery first.", http.StatusConflict)
		return
	}
	fp, expected, _, ok := readNavigationSelection(w, r, "website-check")
	if !ok {
		return
	}
	if !g.startDerivation() {
		http.Error(w, "another key or password check is running", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-g.derive }()
	records, generation, err := instanceaccess.ReadInventory(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
	if err != nil {
		inventoryError(w, err)
		return
	}
	if generation != expected {
		http.Error(w, "Certificates changed. Return and refresh before selecting again.", http.StatusConflict)
		return
	}
	for _, record := range records {
		if record.Fingerprint != fp {
			continue
		}
		current, ready := g.currentSession(r)
		clear(current.dataKey[:])
		if !ready || current.setup || current.revision != s.revision || r.Context().Err() != nil {
			http.Error(w, "session no longer available", http.StatusUnauthorized)
			return
		}
		writeSavedWebsite(w, record, generation)
		return
	}
	http.Error(w, "Certificate no longer saved. Return and refresh.", http.StatusConflict)
}

func writeSavedWebsite(w http.ResponseWriter, record publicinventory.Record, generation uint64) {
	// The public store already validates DER/identity. Recheck at the handoff
	// boundary so an invalid template/record cannot release a partial selection.
	if len(record.DER) == 0 || len(record.DER) > 64<<10 || generation < 1 || generation > 9007199254740991 || !publicinventory.ValidFingerprint(record.Fingerprint) {
		http.Error(w, "Saved certificate unavailable. Return and refresh.", http.StatusConflict)
		return
	}
	cert, err := x509.ParseCertificate(record.DER)
	if err != nil || cert.IsCA {
		http.Error(w, "Select a public website certificate, not a CA certificate.", http.StatusConflict)
		return
	}
	hash := sha256.Sum256(record.DER)
	if strings.ReplaceAll(record.Fingerprint, ":", "") != strings.ToUpper(hex.EncodeToString(hash[:])) {
		http.Error(w, "Saved certificate identity unavailable. Return and refresh.", http.StatusConflict)
		return
	}
	body, err := authAssets.ReadFile("auth/website-check.html")
	if err != nil || len(body) > 1<<20 || bytes.Count(body, []byte(savedWebsiteMarker)) != 1 {
		http.Error(w, "website check unavailable", http.StatusServiceUnavailable)
		return
	}
	// json.Marshal HTML-escapes text. This is inert data, never inline script.
	public, err := json.Marshal(struct {
		Schema      string `json:"schema_version"`
		Fingerprint string `json:"fingerprint"`
		Generation  uint64 `json:"generation"`
		DER         []byte `json:"der"`
	}{"rootwell.website-saved.v1", record.Fingerprint, generation, record.DER})
	if err != nil {
		http.Error(w, "website check unavailable", http.StatusServiceUnavailable)
		return
	}
	body = bytes.Replace(body, []byte(savedWebsiteMarker), []byte(`<div id="website-saved-source" hidden>`+string(public)+`</div>`), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body)
}
