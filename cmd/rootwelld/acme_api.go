package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/acmeplan"
)

func readACMEPlan(w http.ResponseWriter, r *http.Request) (acmeplan.Plan, bool) {
	bad := func() (acmeplan.Plan, bool) {
		http.Error(w, "Choose staging and 1–32 unique ASCII DNS names; wildcards need DNS-01. No setup was saved.", http.StatusBadRequest)
		return acmeplan.Plan{}, false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return acmeplan.Plan{}, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	defer clear(body)
	if err != nil || !utf8.Valid(body) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(body))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return bad()
	}
	seen := map[string]bool{}
	var provider, challenge string
	var domains []string
	for d.More() {
		t, err := d.Token()
		name, ok := t.(string)
		if err != nil || !ok || seen[name] {
			return bad()
		}
		seen[name] = true
		switch name {
		case "provider", "challenge":
			var value *string
			if err := d.Decode(&value); err != nil || value == nil {
				return bad()
			}
			if name == "provider" {
				provider = *value
			} else {
				challenge = *value
			}
		case "domains":
			if err := d.Decode(&domains); err != nil {
				return bad()
			}
		default:
			return bad()
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') {
		return bad()
	}
	if _, err := d.Token(); err != io.EOF || len(seen) != 3 {
		return bad()
	}
	plan, err := acmeplan.Check(provider, challenge, domains)
	if err != nil {
		return bad()
	}
	return plan, true
}

func (g *gate) acmePlanEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !signedIn {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if s.setup {
		http.Error(w, "change setup password first", http.StatusForbidden)
		return
	}
	if !g.sameOrigin(r) {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	plan, ok := readACMEPlan(w, r)
	if !ok {
		return
	}
	if _, current := g.currentSession(r); !current || r.Context().Err() != nil {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(plan)
}
