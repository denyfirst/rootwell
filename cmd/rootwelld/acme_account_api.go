package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"runtime"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type accountInput struct {
	Password string
	Expected uint64
}

// Separate request shapes: status takes only provider; preparation additionally
// requires fresh password, exact generation and explicit true confirmation.
func readAccountInput(w http.ResponseWriter, r *http.Request, prepare bool) (accountInput, bool) {
	var input accountInput
	bad := func() (accountInput, bool) { return accountInput{}, false }
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
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
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
		case "password":
			var value *string
			if !prepare || d.Decode(&value) != nil || value == nil || len(*value) == 0 || len(*value) > 256 {
				return bad()
			}
			input.Password = *value
		case "expected_generation":
			var value *uint64
			if !prepare || d.Decode(&value) != nil || value == nil || *value == 0 || *value > 1_000_000 {
				return bad()
			}
			input.Expected = *value
		case "confirm":
			var value bool
			if !prepare || d.Decode(&value) != nil || !value {
				return bad()
			}
		default:
			return bad()
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || !seen["provider"] || prepare && len(seen) != 4 || !prepare && len(seen) != 1 {
		return bad()
	}
	_, err = d.Token()
	if err != io.EOF {
		return bad()
	}
	return input, true
}

type accountOutput struct {
	Schema         string `json:"schema_version"`
	Provider       string `json:"provider"`
	Generation     uint64 `json:"generation"`
	State          string `json:"state"`
	Fingerprint    string `json:"fingerprint"`
	PreparedAt     string `json:"prepared_at"`
	Saved          bool   `json:"saved"`
	NetworkUsed    bool   `json:"network_used"`
	AccountCreated bool   `json:"account_created"`
	TermsAccepted  bool   `json:"terms_accepted"`
	CanIssue       bool   `json:"can_issue"`
	Registration   string `json:"registration_state"`
}

func (g *gate) acmeAccountEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
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
	prepare := r.URL.Path == "/api/acme/account/prepare"
	input, ok := readAccountInput(w, r, prepare)
	defer func() { input.Password = "" }()
	if !ok {
		http.Error(w, "invalid local account-key request", http.StatusBadRequest)
		return
	}
	if runtime.GOOS != "linux" {
		http.Error(w, "Account-key storage requires Linux or Linux Docker.", http.StatusServiceUnavailable)
		return
	}
	if !s.inventoryReady {
		http.Error(w, "Initialize the encrypted store with full backup and recovery first.", http.StatusConflict)
		return
	}
	if !g.startDerivation() {
		http.Error(w, "another key or password check is running", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-g.derive }()
	if prepare {
		if !g.allowAttempt() {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		setup, err := instanceaccess.Authenticate(g.accessPath, input.Password)
		if err != nil || setup {
			if errors.Is(err, instanceaccess.ErrWrongPassword) {
				http.Error(w, "password not accepted", http.StatusUnauthorized)
			} else {
				http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			}
			return
		}
	}
	permit := func() bool {
		current, ready := g.currentSession(r)
		defer clear(current.dataKey[:])
		return ready && !current.setup && current.revision == s.revision && r.Context().Err() == nil
	}
	if !permit() {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	var status inventorystore.AccountStatus
	var generation uint64
	var err error
	if prepare {
		status, generation, err = instanceaccess.PrepareStagingAccount(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Expected, permit)
	} else {
		status, generation, err = instanceaccess.ReadStagingAccount(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
	}
	if err != nil {
		if errors.Is(err, inventorystore.ErrAccountExists) {
			http.Error(w, "A staging key already exists. Refresh status; no key was replaced.", http.StatusConflict)
		} else {
			inventoryError(w, err)
		}
		return
	}
	if !permit() {
		if prepare {
			http.Error(w, "save outcome uncertain; sign in and refresh status before retrying", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "session no longer available", http.StatusUnauthorized)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if prepare {
		w.WriteHeader(http.StatusCreated)
	}
	_ = json.NewEncoder(w).Encode(accountOutput{Schema: "rootwell.acme.account-key.v1", Provider: acmeplan.Provider, Generation: generation,
		State: status.State, Fingerprint: status.Fingerprint, PreparedAt: status.PreparedAt, Saved: status.State == "key-prepared", Registration: status.Registration,
		AccountCreated: status.Registration == "registered", TermsAccepted: status.Registration == "registered"})
}
