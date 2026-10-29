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

const renewalJobScope = "session-test-renewal"

func readRenewalJobInput(w http.ResponseWriter, r *http.Request, mode string) (watchInput, bool) {
	bad := func() (watchInput, bool) { return watchInput{}, false }
	names := map[string]string{"preview": "provider,fingerprint,expected_generation", "start": "provider,fingerprint,expected_generation,password,confirm,scope,exclusive_dns", "status": "provider", "stop": "provider,job_id"}[mode]
	if names == "" {
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
	for _, n := range strings.Split(names, ",") {
		allowed[n] = true
	}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || !allowed[name] || fields[name] != nil {
			return bad()
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return bad()
		}
		fields[name] = v
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(fields) != len(allowed) {
		return bad()
	}
	if _, err = d.Token(); err != io.EOF {
		return bad()
	}
	str := func(name string) string {
		var v *string
		if json.Unmarshal(fields[name], &v) != nil || v == nil {
			return ""
		}
		return *v
	}
	if str("provider") != acmeplan.Provider {
		return bad()
	}
	input := watchInput{}
	if mode == "preview" || mode == "start" {
		input.Fingerprint = str("fingerprint")
		if !publicinventory.ValidFingerprint(input.Fingerprint) || json.Unmarshal(fields["expected_generation"], &input.Expected) != nil || input.Expected < 1 || input.Expected > 1000000 {
			return bad()
		}
	}
	if mode == "start" {
		var confirm, exclusive bool
		if json.Unmarshal(fields["confirm"], &confirm) != nil || !confirm || json.Unmarshal(fields["exclusive_dns"], &exclusive) != nil || !exclusive || str("scope") != renewalJobScope {
			return bad()
		}
		input.Password = str("password")
		if input.Password == "" || len(input.Password) > 256 {
			return bad()
		}
	}
	if mode == "stop" {
		input.ID = str("job_id")
		raw, err := hex.DecodeString(input.ID)
		if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != input.ID {
			return bad()
		}
	}
	return input, true
}

type renewalJobPlan struct {
	Generation  uint64 `json:"generation"`
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	CanStart    bool   `json:"can_start"`
	Reason      string `json:"reason"`
	Next        string `json:"next_check"`
}

func cyclePlan(p inventorystore.RenewalCycle) *renewalJobPlan {
	d := inventorystore.DecideRenewalCycle(p, inventorystore.RenewalCycleEvents, inventorystore.RenewalCycleBytes, time.Now().UTC())
	return &renewalJobPlan{Generation: p.Generation, Fingerprint: p.Fingerprint, Name: p.Name, CanStart: d.Action != "pause" && d.Action != "complete", Reason: d.Reason, Next: d.Next}
}

type renewalJobOutput struct {
	Schema    string            `json:"schema_version"`
	Provider  string            `json:"provider"`
	Scope     string            `json:"scope"`
	TestOnly  bool              `json:"test_only"`
	CheckedAt string            `json:"checked_at"`
	Job       renewalJobSummary `json:"job"`
	Readiness *renewalJobPlan   `json:"readiness"`
}

func (g *gate) renewalSnapshot(owner [32]byte) renewalJobSummary {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.renewal == nil || g.renewal.owner != owner {
		return summarizeRenewal(nil)
	}
	j := g.renewal
	now := g.now().UTC()
	if activeRenewal(j) && (now.Before(j.last) || !now.Before(j.expires)) {
		g.pauseRenewalLocked(j, "access-ended")
	}
	return summarizeRenewal(j)
}

func (g *gate) renewalJobEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
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
	mode := strings.TrimPrefix(r.URL.Path, "/api/acme/renewal-job/")
	input, ok := readRenewalJobInput(w, r, mode)
	defer func() { input.Password = "" }()
	if !ok {
		http.Error(w, "Choose only the requested session renewal action and its separate DNS permission.", http.StatusBadRequest)
		return
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "session unavailable", http.StatusUnauthorized)
		return
	}
	owner := watchOwner(cookie.Value)
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	started := time.Now()
	permit := func() bool {
		current, ready := g.currentSession(r)
		defer clear(current.dataKey[:])
		return ready && !current.setup && current.revision == s.revision && current.expires == s.expires && ctx.Err() == nil && !time.Now().Before(started)
	}
	if !permit() {
		http.Error(w, "session unavailable", http.StatusUnauthorized)
		return
	}
	var plan *renewalJobPlan
	var created *renewalJob
	if mode == "stop" {
		g.mu.Lock()
		if g.renewal == nil || g.renewal.owner != owner || g.renewal.id != input.ID {
			g.mu.Unlock()
			http.Error(w, "Read current renewal status before stopping it.", http.StatusConflict)
			return
		}
		g.pauseRenewalLocked(g.renewal, "stopped")
		g.mu.Unlock()
	} else if mode != "status" {
		if runtime.GOOS != "linux" || !s.inventoryReady {
			http.Error(w, "Initialize full recovery and encrypted storage in Linux Rootwell first.", http.StatusServiceUnavailable)
			return
		}
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
		p, err := instanceaccess.ReadRenewalCycle(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Expected, input.Fingerprint)
		if err != nil {
			inventoryError(w, err)
			return
		}
		plan = cyclePlan(p)
		if mode == "start" {
			if !plan.CanStart {
				http.Error(w, "Resolve the displayed step before enabling session renewal.", http.StatusConflict)
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
			p, err = instanceaccess.ReadRenewalCycle(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Expected, input.Fingerprint)
			if err != nil || !permit() {
				http.Error(w, "Saved status changed; refresh renewal readiness first.", http.StatusConflict)
				return
			}
			plan = cyclePlan(p)
			if !plan.CanStart {
				http.Error(w, "Resolve the displayed step before enabling session renewal.", http.StatusConflict)
				return
			}
			<-g.derive
			held = false
			created, err = g.newRenewalJob(owner, s, p)
			if err != nil {
				http.Error(w, "A timing watch or renewal is active or finishing. Read its status first.", http.StatusConflict)
				return
			}
		}
	}
	if !permit() {
		if created != nil {
			g.failRenewal(created, "outcome-unconfirmed")
		}
		http.Error(w, "session unavailable; read renewal status after signing in", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(renewalJobOutput{Schema: "rootwell.acme.renewal-job.v1", Provider: acmeplan.Provider, Scope: renewalJobScope, TestOnly: true, CheckedAt: stampWatch(time.Now()), Job: g.renewalSnapshot(owner), Readiness: plan}); err != nil && created != nil {
		g.failRenewal(created, "outcome-unconfirmed")
	}
}
