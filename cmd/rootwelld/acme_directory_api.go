package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/acmestaging"
)

type directoryCheck func(context.Context, func() bool) (acmestaging.Summary, error)

// Exact keys/types, including explicit confirmation; never accept caller URLs,
// account material, domains, or credentials in a reachability check.
func readDirectoryConsent(w http.ResponseWriter, r *http.Request) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	defer clear(body)
	if err != nil || !utf8.Valid(body) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		seen[name] = true
		switch name {
		case "provider":
			var value string
			if d.Decode(&value) != nil || value != acmeplan.Provider {
				return false
			}
		case "confirm":
			var value bool
			if d.Decode(&value) != nil || !value {
				return false
			}
		default:
			return false
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(seen) != 2 {
		return false
	}
	_, err = d.Token()
	return err == io.EOF
}

func (g *gate) acmeDirectoryEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !signedIn {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if s.setup || !g.sameOrigin(r) {
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	if !readDirectoryConsent(w, r) {
		http.Error(w, "Confirm the staging connection. No names, keys or custom URLs are accepted.", http.StatusBadRequest)
		return
	}
	permit := func() bool {
		current, ok := g.currentSession(r)
		return ok && !current.setup && r.Context().Err() == nil
	}
	if !permit() {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	if g.directoryCheck == nil && !acmestaging.Available() {
		http.Error(w, "Provider connections require Linux or Linux Docker. Native preview stays offline.", http.StatusServiceUnavailable)
		return
	}
	// Global bounded RAM state: no queue, no growing per-client map, no persistence.
	g.mu.Lock()
	now := g.now()
	if g.directoryBusy || (!g.directoryLast.IsZero() && now.Sub(g.directoryLast) < 30*time.Second) {
		g.mu.Unlock()
		http.Error(w, "Wait 30 seconds between provider checks.", http.StatusTooManyRequests)
		return
	}
	g.directoryBusy, g.directoryLast = true, now
	g.mu.Unlock()
	defer func() { g.mu.Lock(); g.directoryBusy = false; g.mu.Unlock() }()
	check := g.directoryCheck
	if check == nil {
		check = acmestaging.Discover
	}
	result, err := check(r.Context(), permit)
	if !permit() {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "Provider connection could not be safely checked. No account or certificate was created.", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(result)
}
