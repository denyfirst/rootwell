package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/websitechain"
	"github.com/denyfirst/rootwell/internal/websiteprobe"
)

type websiteCheck func(context.Context, string, func() bool) (websitechain.Report, error)

func readWebsiteConsent(w http.ResponseWriter, r *http.Request) (string, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return "", false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	defer clear(body)
	if err != nil || !utf8.Valid(body) {
		return "", false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return "", false
	}
	seen := map[string]bool{}
	var target string
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return "", false
		}
		seen[name] = true
		switch name {
		case "target":
			if d.Decode(&target) != nil {
				return "", false
			}
		case "confirm":
			var confirmed bool
			if d.Decode(&confirmed) != nil || !confirmed {
				return "", false
			}
		default:
			return "", false
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(seen) != 2 {
		return "", false
	}
	if _, err = d.Token(); err != io.EOF {
		return "", false
	}
	host, err := websiteprobe.ParseTarget(target)
	return host, err == nil
}

func (g *gate) websiteCheckEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	defer clear(s.dataKey[:])
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
	host, valid := readWebsiteConsent(w, r)
	if !valid {
		http.Error(w, "Enter a public DNS name or HTTPS origin and confirm this one website check. Paths, IP addresses, credentials and custom ports are not accepted.", http.StatusBadRequest)
		return
	}
	permit := func() bool {
		current, ok := g.currentSession(r)
		defer clear(current.dataKey[:])
		g.mu.Lock()
		closed := g.closed
		g.mu.Unlock()
		return !closed && ok && !current.setup && current.revision == s.revision && r.Context().Err() == nil
	}
	if !permit() {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	if g.websiteCheck == nil && !websiteprobe.Available() {
		http.Error(w, websiteprobe.ErrUnavailable.Error(), http.StatusServiceUnavailable)
		return
	}
	g.mu.Lock()
	now := g.now()
	if g.websiteBusy || (!g.websiteLast.IsZero() && now.Sub(g.websiteLast) < 30*time.Second) {
		g.mu.Unlock()
		w.Header().Set("Retry-After", "30")
		http.Error(w, "Wait 30 seconds between website checks.", http.StatusTooManyRequests)
		return
	}
	g.websiteBusy, g.websiteLast = true, now
	g.mu.Unlock()
	defer func() { g.mu.Lock(); g.websiteBusy = false; g.mu.Unlock() }()
	check := g.websiteCheck
	if check == nil {
		check = websiteprobe.Probe
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	result, err := check(ctx, host, permit)
	if !permit() || ctx.Err() != nil {
		http.Error(w, "session or check no longer available", http.StatusUnauthorized)
		return
	}
	if err != nil {
		message := websiteprobe.ErrConnection.Error()
		if errors.Is(err, websiteprobe.ErrBlocked) {
			message = websiteprobe.ErrBlocked.Error()
		}
		if errors.Is(err, websiteprobe.ErrTrustStore) {
			message = websiteprobe.ErrTrustStore.Error()
		}
		http.Error(w, message, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(result)
}
