package main

import (
	"bytes"
	"context"
	"encoding/hex"
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
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

const watchScope = "session-timing-only"

type watchInput struct {
	Fingerprint, Password, ID string
	Expected                  uint64
}

func readWatchInput(w http.ResponseWriter, r *http.Request, mode string) (watchInput, bool) {
	bad := func() (watchInput, bool) { return watchInput{}, false }
	var names string
	switch mode {
	case "preview":
		names = "provider,fingerprint,expected_generation"
	case "start":
		names = "provider,fingerprint,expected_generation,password,confirm,scope"
	case "status":
		names = "provider"
	case "stop":
		names = "provider,watch_id"
	default:
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
	fields := map[string]json.RawMessage{}
	allowed := map[string]bool{}
	for _, name := range strings.Split(names, ",") {
		allowed[name] = true
	}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] != nil || !allowed[key] {
			return bad()
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return bad()
		}
		fields[key] = value
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(fields) != len(strings.Split(names, ",")) {
		return bad()
	}
	if _, err = d.Token(); err != io.EOF {
		return bad()
	}
	str := func(key string) string {
		var value *string
		if json.Unmarshal(fields[key], &value) != nil || value == nil {
			return ""
		}
		return *value
	}
	if str("provider") != acmeplan.Provider {
		return bad()
	}
	var input watchInput
	if mode == "preview" || mode == "start" {
		input.Fingerprint = str("fingerprint")
		if !publicinventory.ValidFingerprint(input.Fingerprint) || json.Unmarshal(fields["expected_generation"], &input.Expected) != nil || input.Expected < 1 || input.Expected > 1000000 {
			return bad()
		}
	}
	if mode == "start" {
		var confirm bool
		if json.Unmarshal(fields["confirm"], &confirm) != nil || !confirm || str("scope") != watchScope {
			return bad()
		}
		input.Password = str("password")
		if input.Password == "" || len(input.Password) > 256 {
			return bad()
		}
	}
	if mode == "stop" {
		input.ID = str("watch_id")
		raw, err := hex.DecodeString(input.ID)
		if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != input.ID {
			return bad()
		}
	}
	return input, true
}

type watchReadiness struct {
	Generation  uint64 `json:"generation"`
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	CanStart    bool   `json:"can_start"`
	Reason      string `json:"reason"`
	Recovery    string `json:"recovery"`
	NextCheck   string `json:"next_check"`
}

func watchPlan(p inventorystore.TimingReadiness) *watchReadiness {
	return &watchReadiness{p.Generation, p.Timing.Fingerprint, p.Name, p.CanStart, p.Reason, p.Recovery, p.NextCheck}
}

type watchOutput struct {
	Schema           string          `json:"schema_version"`
	Provider         string          `json:"provider"`
	CheckedAt        string          `json:"checked_at"`
	Scope            string          `json:"scope"`
	AutomaticRenewal bool            `json:"automatic_renewal"`
	Watch            watchSummary    `json:"watch"`
	Readiness        *watchReadiness `json:"readiness"`
}

func (g *gate) watchSnapshot(owner [32]byte) watchSummary {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.watch == nil || g.watch.owner != owner {
		return summarizeWatch(nil)
	}
	w := g.watch
	now := g.now().UTC()
	if activeWatch(w) && (now.Before(w.last) || !now.Before(w.expires)) {
		g.pauseWatchLocked(w, "access-ended", "none")
	}
	return summarizeWatch(w)
}

func (g *gate) timingWatchEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	defer clear(s.dataKey[:])
	if r.Method != "POST" {
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
	mode := strings.TrimPrefix(r.URL.Path, "/api/acme/timing-watch/")
	input, ok := readWatchInput(w, r, mode)
	defer func() { input.Password = "" }()
	if !ok {
		http.Error(w, "Choose only the requested timing-watch action and its separate permission.", http.StatusBadRequest)
		return
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "session unavailable", http.StatusUnauthorized)
		return
	}
	owner := watchOwner(cookie.Value)
	started := time.Now().UTC()
	permit := func() bool {
		current, ready := g.currentSession(r)
		defer clear(current.dataKey[:])
		return ready && !current.setup && current.revision == s.revision && r.Context().Err() == nil && !time.Now().UTC().Before(started)
	}
	if !permit() {
		http.Error(w, "session unavailable", http.StatusUnauthorized)
		return
	}
	var plan *watchReadiness
	var created *timingWatch
	if mode == "stop" {
		g.mu.Lock()
		if g.watch == nil || g.watch.owner != owner || g.watch.id != input.ID {
			g.mu.Unlock()
			http.Error(w, "Read current watch status before stopping it.", http.StatusConflict)
			return
		}
		g.pauseWatchLocked(g.watch, "stopped", "none")
		g.mu.Unlock()
	} else if mode != "status" {
		if runtime.GOOS != "linux" || !s.inventoryReady {
			http.Error(w, "Initialize full recovery and encrypted storage in Linux Rootwell first.", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		if !g.startDerivation() {
			http.Error(w, "another key or password check is running", http.StatusServiceUnavailable)
			return
		}
		held := true
		defer func() {
			if held {
				<-g.derive
			}
		}()
		p, err := instanceaccess.ReadTimingReadiness(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Expected, input.Fingerprint, time.Now().UTC())
		if err != nil {
			inventoryError(w, err)
			return
		}
		plan = watchPlan(p)
		if mode == "start" {
			if !p.CanStart {
				http.Error(w, "Resolve the displayed recovery step before enabling automatic timing checks.", http.StatusConflict)
				return
			}
			if !g.allowAttempt() {
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
				http.Error(w, "session unavailable", http.StatusUnauthorized)
				return
			}
			// Revalidate after fresh authentication. No guessed/adopted generation.
			p, err = instanceaccess.ReadTimingReadiness(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Expected, input.Fingerprint, time.Now().UTC())
			if err != nil || !p.CanStart || !permit() {
				http.Error(w, "Saved status changed; refresh renewal readiness first.", http.StatusConflict)
				return
			}
			plan = watchPlan(p)
			<-g.derive
			held = false
			created, err = g.newTimingWatch(owner, s, input.Fingerprint, p.Name, input.Expected)
			if err != nil {
				http.Error(w, "A watch is active or finishing. Read its status first.", http.StatusConflict)
				return
			}
		}
	}
	if !permit() {
		if created != nil {
			g.failTimingWatch(created, "outcome-unconfirmed", "readiness")
		}
		http.Error(w, "session unavailable; refresh watch status after signing in", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(watchOutput{Schema: "rootwell.acme.timing-watch.v1", Provider: acmeplan.Provider, CheckedAt: stampWatch(time.Now()), Scope: watchScope, Watch: g.watchSnapshot(owner), Readiness: plan}); err != nil && created != nil {
		g.failTimingWatch(created, "outcome-unconfirmed", "readiness")
	}
}
