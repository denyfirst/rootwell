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

	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type dnsConnect func(context.Context, func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error)

type dnsOperationInput struct {
	Password string
	Expected uint64
	Index    int
}

func readDNSOperationInput(w http.ResponseWriter, r *http.Request, mode string) (dnsOperationInput, bool) {
	bad := func() (dnsOperationInput, bool) { return dnsOperationInput{}, false }
	if mode != "status" && mode != "add" && mode != "check" && mode != "cleanup" {
		return bad()
	}
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
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return bad()
	}
	input := dnsOperationInput{Index: -1}
	seen := map[string]bool{}
	for d.More() {
		t, err := d.Token()
		name, ok := t.(string)
		if err != nil || !ok || seen[name] {
			return bad()
		}
		seen[name] = true
		switch name {
		case "provider":
			var v *string
			if d.Decode(&v) != nil || v == nil || *v != "cloudflare" {
				return bad()
			}
		case "password":
			var v *string
			if mode == "status" || d.Decode(&v) != nil || v == nil || len(*v) == 0 || len(*v) > 256 {
				return bad()
			}
			input.Password = *v
		case "expected_generation":
			var v *uint64
			if mode == "status" || d.Decode(&v) != nil || v == nil || *v < 1 || *v > 1000000 {
				return bad()
			}
			input.Expected = *v
		case "index":
			var v *int
			if mode == "status" || d.Decode(&v) != nil || v == nil || *v < 0 || *v > 7 {
				return bad()
			}
			input.Index = *v
		case "confirm", "exclusive":
			var v *bool
			if mode == "status" || name == "exclusive" && mode != "cleanup" || d.Decode(&v) != nil || v == nil || !*v {
				return bad()
			}
		default:
			return bad()
		}
	}
	end, err := d.Token()
	want := 5
	if mode == "status" {
		want = 1
	}
	if mode == "cleanup" {
		want = 6
	}
	if err != nil || end != json.Delim('}') || len(seen) != want || !seen["provider"] || mode != "status" && (!seen["confirm"] || !seen["password"] || !seen["expected_generation"] || !seen["index"]) || mode == "cleanup" && !seen["exclusive"] {
		return bad()
	}
	_, err = d.Token()
	if err != io.EOF {
		return bad()
	}
	return input, true
}

type dnsOperationOutput struct {
	Schema         string   `json:"schema_version"`
	Provider       string   `json:"provider"`
	Generation     uint64   `json:"generation"`
	Network        bool     `json:"network_used"`
	ZoneName       string   `json:"zone_name"`
	ServerTime     string   `json:"server_time"`
	CanPrepare     bool     `json:"can_prepare"`
	PendingDomains []string `json:"pending_domains"`
	inventorystore.DNSPlanStatus
}

// Every component must have the same generation, or nothing is published. The
// writer below independently repeats exact revision/generation while locked.
func (g *gate) readDNSOperation(s session) (dnsOperationOutput, error) {
	bad := func() (dnsOperationOutput, error) { return dnsOperationOutput{}, inventorystore.ErrStaleGeneration }
	plan, gen, err := instanceaccess.ReadStagingDNSPlan(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
	if err != nil {
		return dnsOperationOutput{}, err
	}
	config, cg, err := instanceaccess.ReadCloudflareConfig(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
	if err != nil || cg != gen {
		return bad()
	}
	order, _, issuance, og, err := instanceaccess.ReadStagingOrderLifecycle(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
	if err != nil || og != gen {
		return bad()
	}
	now := time.Now().UTC()
	if now.Year() < 2020 || now.Year() > 2100 {
		return bad()
	}
	result := dnsOperationOutput{Schema: "rootwell.dns.operation.v1", Provider: "cloudflare", Generation: gen, ZoneName: config.ZoneName, ServerTime: now.Format("2006-01-02T15:04:05Z"), PendingDomains: []string{}, DNSPlanStatus: plan}
	if !plan.Prepared && config.State == "saved" && (order.State == "dns-ready" || order.State == "dns-acknowledged") && issuance.State == "not-started" && order.Expires > result.ServerTime {
		for _, row := range order.Records {
			base := strings.TrimPrefix(row.Domain, "*.")
			if row.Required {
				if base != config.ZoneName && !strings.HasSuffix(base, "."+config.ZoneName) {
					result.PendingDomains = []string{}
					return result, nil
				}
				result.PendingDomains = append(result.PendingDomains, row.Domain)
			}
		}
		result.CanPrepare = len(result.PendingDomains) > 0
		if result.CanPrepare {
			result.Expires = order.Expires
		}
	}
	return result, nil
}

func (g *gate) dnsOperationEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
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
	mode := strings.TrimPrefix(r.URL.Path, "/api/acme/dns/")
	input, ok := readDNSOperationInput(w, r, mode)
	defer func() { input.Password = "" }()
	if !ok {
		http.Error(w, "invalid DNS operation", http.StatusBadRequest)
		return
	}
	if runtime.GOOS != "linux" || !acmestaging.Available() {
		http.Error(w, "DNS operations require Linux or Linux Docker.", http.StatusServiceUnavailable)
		return
	}
	if !s.inventoryReady {
		http.Error(w, "Initialize the encrypted store and full recovery first.", http.StatusConflict)
		return
	}
	if mode != "status" && http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30*time.Second)) != nil {
		http.Error(w, "bounded response unavailable", http.StatusServiceUnavailable)
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
	permit := func() bool {
		current, ready := g.currentSession(r)
		defer clear(current.dataKey[:])
		return ready && !current.setup && current.revision == s.revision && ctx.Err() == nil
	}
	if !permit() {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	output, err := g.readDNSOperation(s)
	if err != nil {
		inventoryError(w, err)
		return
	}
	if mode != "status" {
		if input.Expected != output.Generation {
			http.Error(w, "Saved status changed. Refresh first.", http.StatusConflict)
			return
		}
		rows := output.Records
		valid := input.Index >= 0 && (output.Prepared && input.Index < len(rows) || !output.Prepared && output.CanPrepare && input.Index < len(output.PendingDomains))
		if valid && output.Prepared {
			row := rows[input.Index]
			cleanup := mode == "cleanup" || mode == "check" && row.State == "deleting"
			valid = mode == "add" && row.State == "new" && output.Expires > output.ServerTime || mode == "check" && (row.State == "creating" || row.State == "deleting") || mode == "cleanup" && row.State == "created"
			if cleanup {
				valid = valid && !row.CleanupBlocked && row.CleanupAttempts < 6 && (row.CleanupNotBefore == "" || row.CleanupNotBefore <= output.ServerTime)
			} else {
				valid = valid && !row.Blocked && row.Attempts < 6 && (row.NotBefore == "" || row.NotBefore <= output.ServerTime)
			}
		} else if valid {
			valid = mode == "add"
		}
		if !valid {
			http.Error(w, "This DNS action is unavailable. Read saved DNS status; respect the wait or resolve the existing record, never reset it.", http.StatusConflict)
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
		if !g.startRegistrationProvider(false) {
			http.Error(w, "Wait 30 seconds between provider operations.", http.StatusTooManyRequests)
			return
		}
		defer func() { g.mu.Lock(); g.directoryBusy = false; g.mu.Unlock() }()
		connect := g.dnsConnect
		if connect == nil {
			connect = acmestaging.CloudflareTXT
		}
		_, gen, err := instanceaccess.RunStagingDNS(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Expected, input.Index, mode, permit, func(allowed func() bool, token []byte, scope dnsrecord.Scope, state dnsrecord.State, cleanup, readOnly bool, checkpoint func(dnsrecord.State) error) (dnsrecord.State, error) {
			return connect(ctx, allowed, token, scope, state, cleanup, readOnly, checkpoint)
		})
		if err != nil || !permit() {
			http.Error(w, "DNS outcome not confirmed. Read saved DNS status first. Do not repeat a create or deletion; a sent operation cannot be undone.", http.StatusServiceUnavailable)
			return
		}
		output, err = g.readDNSOperation(s)
		if err != nil || output.Generation != gen {
			http.Error(w, "Saved status changed. Refresh first.", http.StatusConflict)
			return
		}
		output.Network = true
	}
	if !permit() {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(output)
}
