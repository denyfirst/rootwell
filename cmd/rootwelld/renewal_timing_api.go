package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

type timingConnect func(context.Context, func() bool, []byte) (renewalrecord.Observation, error)
type timingInput struct {
	Fingerprint, Password string
	Expected              uint64
}

// No URL, DER, window, key, job consent or client result is accepted. The only
// source is the exact authenticated saved completion selected by fingerprint.
func readTimingInput(w http.ResponseWriter, r *http.Request, mode string) (timingInput, bool) {
	bad := func() (timingInput, bool) { return timingInput{}, false }
	if mode != "status" && mode != "check" && mode != "interrupt" {
		return bad()
	}
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
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return bad()
	}
	var input timingInput
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
			var v string
			if d.Decode(&v) != nil || v != acmeplan.Provider {
				return bad()
			}
		case "fingerprint":
			if d.Decode(&input.Fingerprint) != nil || !publicinventory.ValidFingerprint(input.Fingerprint) {
				return bad()
			}
		case "expected_generation":
			if d.Decode(&input.Expected) != nil || input.Expected < 1 || input.Expected > 1000000 {
				return bad()
			}
		case "password":
			if mode == "status" || d.Decode(&input.Password) != nil || input.Password == "" || len(input.Password) > 256 {
				return bad()
			}
		case "confirm":
			var v bool
			if mode == "status" || d.Decode(&v) != nil || !v {
				return bad()
			}
		default:
			return bad()
		}
	}
	count := 3
	if mode != "status" {
		count = 5
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(seen) != count || !seen["provider"] || !seen["fingerprint"] || !seen["expected_generation"] || mode != "status" && (!seen["password"] || !seen["confirm"]) {
		return bad()
	}
	_, err = d.Token()
	if err != io.EOF {
		return bad()
	}
	return input, true
}

type timingOutput struct {
	Schema           string                             `json:"schema_version"`
	Provider         string                             `json:"provider"`
	Generation       uint64                             `json:"generation"`
	CheckedAt        string                             `json:"checked_at"`
	UnlockExpires    string                             `json:"unlock_expires"`
	NetworkAttempted bool                               `json:"network_attempted"`
	Saved            bool                               `json:"saved"`
	AutomaticRenewal bool                               `json:"automatic_renewal"`
	Status           inventorystore.RenewalTimingStatus `json:"status"`
}

func (g *gate) renewalTimingEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
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
		if http.NewResponseController(w).SetReadDeadline(time.Now().Add(5*time.Second)) != nil || http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30*time.Second)) != nil {
			http.Error(w, "bounded request unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	mode := strings.TrimPrefix(r.URL.Path, "/api/acme/renewal-timing/")
	if mode != "status" && mode != "check" && mode != "interrupt" {
		http.NotFound(w, r)
		return
	}
	input, ok := readTimingInput(w, r, mode)
	defer func() { input.Password = "" }()
	if !ok {
		http.Error(w, "Choose a saved certificate and confirm the requested operation only.", http.StatusBadRequest)
		return
	}
	if runtime.GOOS != "linux" || !acmestaging.Available() {
		http.Error(w, "Saved renewal timing requires Linux or Linux Docker.", http.StatusServiceUnavailable)
		return
	}
	if !s.inventoryReady {
		http.Error(w, "Initialize encrypted storage and full recovery first.", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if !g.startDerivation() {
		http.Error(w, "another key or password check is running", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-g.derive }()
	started := time.Now().UTC()
	permit := func() bool {
		current, ready := g.currentSession(r)
		defer clear(current.dataKey[:])
		return ready && !current.setup && current.revision == s.revision && r.Context().Err() == nil && !time.Now().UTC().Before(started)
	}
	if !permit() {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	status, gen, err := instanceaccess.ReadStagingRenewalTiming(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Expected, input.Fingerprint)
	if err != nil {
		inventoryError(w, err)
		return
	}
	if mode != "status" {
		if mode == "check" && !status.CanRead || mode == "interrupt" && !status.CanInterrupt {
			http.Error(w, "Read saved status first. This operation is not currently available.", http.StatusConflict)
			return
		}
		if !g.allowAttempt() {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		setup, err := instanceaccess.Authenticate(g.accessPath, input.Password)
		input.Password = ""
		if err != nil || setup {
			if errors.Is(err, instanceaccess.ErrWrongPassword) {
				http.Error(w, "password not accepted", http.StatusUnauthorized)
			} else {
				http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		if !permit() {
			http.Error(w, "session no longer available", http.StatusUnauthorized)
			return
		}
		if mode == "check" {
			if !g.startRegistrationProvider(false) {
				http.Error(w, "Wait 30 seconds between provider operations.", http.StatusTooManyRequests)
				return
			}
			defer func() { g.mu.Lock(); g.directoryBusy = false; g.mu.Unlock() }()
			connect := g.timingConnect
			if connect == nil {
				connect = acmestaging.RenewalInformation
			}
			status, gen, err = instanceaccess.RunStagingRenewalTiming(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, gen, input.Fingerprint, permit, func(allowed func() bool, der []byte) (renewalrecord.Observation, error) {
				return connect(r.Context(), allowed, der)
			})
		} else {
			status, gen, err = instanceaccess.InterruptStagingRenewalTiming(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, gen, input.Fingerprint, permit)
		}
		if err != nil {
			if providerWaitError(w, err) {
				return
			}
			http.Error(w, "Outcome not confirmed. Refresh saved timing; do not repeat an interrupted check.", http.StatusServiceUnavailable)
			return
		}
	}
	// Re-read the exact final snapshot and live permission before publication.
	status, again, err := instanceaccess.ReadStagingRenewalTiming(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, gen, input.Fingerprint)
	if err != nil || again != gen || !permit() {
		http.Error(w, "Saved status changed or access ended. Refresh first.", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(timingOutput{Schema: "rootwell.acme.renewal-timing.v1", Provider: acmeplan.Provider, Generation: gen, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), UnlockExpires: s.expires.UTC().Format(time.RFC3339), NetworkAttempted: mode == "check", Saved: mode != "status", Status: status})
}
