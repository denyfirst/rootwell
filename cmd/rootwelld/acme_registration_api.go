package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"runtime"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type termsCheck func(context.Context, func() bool) (string, error)
type accountRegister func(context.Context, func() bool, crypto.Signer, string) (string, bool, error)
type accountFind func(context.Context, func() bool, crypto.Signer) (string, bool, error)

type registrationPreview struct {
	token, session, revision [32]byte
	generation               uint64
	fingerprint, terms       string
	issued, expires          time.Time
}

type registrationInput struct {
	expected          uint64
	password, preview string
}

// The three exact shapes do not accept keys, domain/contact data, account URLs,
// arbitrary terms URLs or a caller-selected CA. Duplicate/null/trailing fail.
func readRegistrationInput(w http.ResponseWriter, r *http.Request, mode string) (registrationInput, bool) {
	bad := func() (registrationInput, bool) { return registrationInput{}, false }
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return bad()
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	defer clear(body)
	if err != nil || !utf8.Valid(body) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(body))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return bad()
	}
	input := registrationInput{}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return bad()
		}
		seen[name] = true
		switch name {
		case "provider":
			var value string
			if d.Decode(&value) != nil || value != acmeplan.Provider {
				return bad()
			}
		case "confirm":
			var value bool
			if d.Decode(&value) != nil || !value {
				return bad()
			}
		case "expected_generation":
			var value *uint64
			if d.Decode(&value) != nil || value == nil || *value < 1 || *value > 1_000_000 {
				return bad()
			}
			input.expected = *value
		case "password":
			var value *string
			if mode == "preview" || d.Decode(&value) != nil || value == nil || len(*value) == 0 || len(*value) > 256 {
				return bad()
			}
			input.password = *value
		case "preview":
			var value string
			if mode != "register" || d.Decode(&value) != nil || len(value) != 43 {
				return bad()
			}
			raw, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != value {
				return bad()
			}
			input.preview = value
		case "terms_agreed":
			var value bool
			if mode != "register" || d.Decode(&value) != nil || !value {
				return bad()
			}
		default:
			return bad()
		}
	}
	token, err = d.Token()
	count := 4
	if mode == "preview" {
		count = 3
	}
	if mode == "register" {
		count = 6
	}
	if err != nil || token != json.Delim('}') || len(seen) != count || !seen["provider"] || !seen["confirm"] || !seen["expected_generation"] || (mode != "preview" && !seen["password"]) || (mode == "register" && (!seen["preview"] || !seen["terms_agreed"])) {
		return bad()
	}
	_, err = d.Token()
	if err != io.EOF {
		return bad()
	}
	return input, true
}

func (g *gate) startRegistrationProvider(skipCooldown bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if g.directoryBusy || (!skipCooldown && !g.directoryLast.IsZero() && now.Sub(g.directoryLast) < 30*time.Second) {
		return false
	}
	g.directoryBusy = true
	g.directoryLast = now
	return true
}

func (g *gate) acmeRegistrationEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
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
	mode := "preview"
	if r.URL.Path == "/api/acme/registration/register" {
		mode = "register"
	}
	if r.URL.Path == "/api/acme/registration/reconcile" {
		mode = "reconcile"
	}
	input, ok := readRegistrationInput(w, r, mode)
	defer func() { input.password = "" }()
	if !ok {
		http.Error(w, "invalid staging registration request", http.StatusBadRequest)
		return
	}
	if runtime.GOOS != "linux" || !acmestaging.Available() {
		http.Error(w, "Staging registration requires Linux or Linux Docker.", http.StatusServiceUnavailable)
		return
	}
	if !s.inventoryReady {
		http.Error(w, "Initialize the encrypted store and full recovery first.", http.StatusConflict)
		return
	}
	if !g.startDerivation() {
		http.Error(w, "another key or password check is running", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-g.derive }()
	permit := func() bool {
		current, ready := g.currentSession(r)
		defer clear(current.dataKey[:])
		return ready && !current.setup && current.revision == s.revision && r.Context().Err() == nil
	}
	if !permit() {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	status, generation, err := instanceaccess.ReadStagingAccount(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
	if err != nil {
		inventoryError(w, err)
		return
	}
	if generation != input.expected || status.State != "key-prepared" || (mode == "reconcile" && status.Registration != "registration-pending") || (mode != "reconcile" && status.Registration != "not-registered") {
		http.Error(w, "Saved status changed. Refresh before proceeding.", http.StatusConflict)
		return
	}
	if mode != "preview" {
		if !g.allowAttempt() {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		setup, err := instanceaccess.Authenticate(g.accessPath, input.password)
		input.password = ""
		if err != nil || setup {
			if errors.Is(err, instanceaccess.ErrWrongPassword) {
				http.Error(w, "password not accepted", http.StatusUnauthorized)
			} else {
				http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			}
			return
		}
	}
	if !permit() {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	var terms string
	if mode == "register" {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			http.Error(w, "preview unavailable", http.StatusConflict)
			return
		}
		g.mu.Lock()
		preview := g.registrationPreview
		now := g.now()
		valid := preview != nil && preview.token == sha256.Sum256([]byte(input.preview)) && preview.session == sha256.Sum256([]byte(cookie.Value)) && preview.revision == s.revision && preview.generation == generation && preview.fingerprint == status.Fingerprint && !now.Before(preview.issued) && now.Before(preview.expires)
		if valid {
			terms = preview.terms
			g.registrationPreview = nil
		}
		g.mu.Unlock()
		if !valid {
			http.Error(w, "Refresh provider terms and confirm again.", http.StatusConflict)
			return
		}
	}
	if !g.startRegistrationProvider(mode == "register") {
		http.Error(w, "Wait 30 seconds between provider checks.", http.StatusTooManyRequests)
		return
	}
	defer func() { g.mu.Lock(); g.directoryBusy = false; g.mu.Unlock() }()
	if mode == "preview" {
		g.mu.Lock()
		g.registrationPreview = nil
		g.mu.Unlock()
		check := g.registrationTerms
		if check == nil {
			check = acmestaging.RegistrationTerms
		}
		terms, err = check(r.Context(), permit)
		if err != nil || !permit() || !inventorystore.ValidStagingTermsURL(terms) {
			http.Error(w, "Current provider terms could not be safely checked. Nothing was registered.", http.StatusBadGateway)
			return
		}
		// Revalidate the exact store after the external read, before issuing proof.
		again, gen, err := instanceaccess.ReadStagingAccount(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
		if err != nil || again != status || gen != generation || !permit() {
			http.Error(w, "Saved status changed. Refresh before proceeding.", http.StatusConflict)
			return
		}
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			http.Error(w, "session no longer available", http.StatusUnauthorized)
			return
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			http.Error(w, "preview unavailable", http.StatusServiceUnavailable)
			return
		}
		token := base64.RawURLEncoding.EncodeToString(raw)
		clear(raw)
		now := g.now().UTC().Truncate(time.Second)
		expires := now.Add(5 * time.Minute)
		if now.Year() < 2020 || expires.Year() > 9999 {
			http.Error(w, "clock unavailable", http.StatusServiceUnavailable)
			return
		}
		g.mu.Lock()
		g.registrationPreview = &registrationPreview{token: sha256.Sum256([]byte(token)), session: sha256.Sum256([]byte(cookie.Value)), revision: s.revision, generation: generation, fingerprint: status.Fingerprint, terms: terms, issued: now, expires: expires}
		g.mu.Unlock()
		if !permit() {
			g.mu.Lock()
			g.registrationPreview = nil
			g.mu.Unlock()
			http.Error(w, "session no longer available", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(struct {
			Schema      string `json:"schema_version"`
			Provider    string `json:"provider"`
			Generation  uint64 `json:"generation"`
			Fingerprint string `json:"fingerprint"`
			Terms       string `json:"terms_url"`
			Preview     string `json:"preview"`
			Expires     string `json:"expires_at"`
			Network     bool   `json:"network_used"`
			CanIssue    bool   `json:"can_issue"`
		}{"rootwell.acme.registration-preview.v1", acmeplan.Provider, generation, status.Fingerprint, terms, token, expires.Format("2006-01-02T15:04:05Z"), true, false})
		return
	}
	create := g.registrationCreate
	if create == nil {
		create = acmestaging.RegisterAccount
	}
	find := g.registrationFind
	if find == nil {
		find = acmestaging.FindAccount
	}
	result, gen, err := instanceaccess.RunStagingRegistration(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, generation, terms, mode == "reconcile", permit, func(signer crypto.Signer, accepted string) (string, bool, error) {
		if mode == "reconcile" {
			return find(r.Context(), permit, signer)
		}
		return create(r.Context(), permit, signer, accepted)
	})
	if err != nil || !permit() {
		http.Error(w, "Outcome not confirmed. Refresh saved status, then check the existing account with the same key. No key was replaced.", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		Schema      string `json:"schema_version"`
		Provider    string `json:"provider"`
		Generation  uint64 `json:"generation"`
		Fingerprint string `json:"fingerprint"`
		State       string `json:"state"`
		Network     bool   `json:"network_used"`
		Saved       bool   `json:"saved"`
		CanIssue    bool   `json:"can_issue"`
	}{"rootwell.acme.registration.v1", acmeplan.Provider, gen, result.Fingerprint, result.Registration, true, true, false})
}
