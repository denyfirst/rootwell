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

	"github.com/denyfirst/rootwell/internal/cloudflareconfig"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type dnsConfigInput struct {
	Password string
	Expected uint64
	ZoneID   string
	ZoneName string
	Token    []byte
}

func readDNSConfigInput(w http.ResponseWriter, r *http.Request, mode string) (dnsConfigInput, bool) {
	var input dnsConfigInput
	bad := func() (dnsConfigInput, bool) { clear(input.Token); input.Password = ""; return dnsConfigInput{}, false }
	if mode != "status" && mode != "save" && mode != "remove" {
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
			var value *string
			if d.Decode(&value) != nil || value == nil || *value != "cloudflare" {
				return bad()
			}
		case "password":
			var value *string
			if mode == "status" || d.Decode(&value) != nil || value == nil || len(*value) == 0 || len(*value) > 256 {
				return bad()
			}
			input.Password = *value
		case "expected_generation":
			var value *uint64
			if mode == "status" || d.Decode(&value) != nil || value == nil || *value == 0 || *value > 1_000_000 {
				return bad()
			}
			input.Expected = *value
		case "confirm":
			var value *bool
			if mode == "status" || d.Decode(&value) != nil || value == nil || !*value {
				return bad()
			}
		case "zone_id", "zone_name", "token":
			var value *string
			if mode != "save" || d.Decode(&value) != nil || value == nil || len(*value) > 256 {
				return bad()
			}
			switch name {
			case "zone_id":
				input.ZoneID = *value
			case "zone_name":
				input.ZoneName = *value
			case "token":
				input.Token = []byte(*value)
			}
		default:
			return bad()
		}
	}
	token, err = d.Token()
	want := 1
	if mode == "remove" {
		want = 4
	}
	if mode == "save" {
		want = 7
	}
	if err != nil || token != json.Delim('}') || !seen["provider"] || len(seen) != want {
		return bad()
	}
	if _, err := d.Token(); err != io.EOF {
		return bad()
	}
	if mode == "save" && !cloudflareconfig.Valid(input.ZoneID, input.ZoneName, input.Token) {
		return bad()
	}
	return input, true
}

type dnsConfigOutput struct {
	Schema        string `json:"schema_version"`
	Provider      string `json:"provider"`
	Generation    uint64 `json:"generation"`
	State         string `json:"state"`
	ZoneName      string `json:"zone_name"`
	SavedAt       string `json:"saved_at"`
	CanChange     bool   `json:"can_change"`
	NetworkUsed   bool   `json:"network_used"`
	TokenVerified bool   `json:"token_verified"`
	DNSChanged    bool   `json:"dns_changed"`
}

func (g *gate) cloudflareConfigEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
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
	mode := "status"
	if r.URL.Path == "/api/dns/cloudflare/save" {
		mode = "save"
	}
	if r.URL.Path == "/api/dns/cloudflare/remove" {
		mode = "remove"
	}
	input, ok := readDNSConfigInput(w, r, mode)
	defer func() { clear(input.Token); input.Password = "" }()
	if !ok {
		http.Error(w, "invalid local DNS credential request", http.StatusBadRequest)
		return
	}
	if runtime.GOOS != "linux" {
		http.Error(w, "DNS credential storage requires Linux or Linux Docker.", http.StatusServiceUnavailable)
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
	if mode != "status" {
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
	var status inventorystore.CloudflareStatus
	var generation uint64
	var err error
	if mode == "status" {
		status, generation, err = instanceaccess.ReadCloudflareConfig(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
	} else {
		status, generation, err = instanceaccess.ChangeCloudflareConfig(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Expected, input.ZoneID, input.ZoneName, input.Token, mode == "remove", permit)
	}
	if err != nil {
		if errors.Is(err, inventorystore.ErrDNSConfigInUse) {
			http.Error(w, "Close the saved certificate request before changing or removing DNS credentials.", http.StatusConflict)
		} else {
			inventoryError(w, err)
		}
		return
	}
	if !permit() {
		http.Error(w, "outcome not confirmed; sign in and check saved DNS settings before retrying", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(dnsConfigOutput{Schema: "rootwell.dns.config.v1", Provider: "cloudflare", Generation: generation, State: status.State, ZoneName: status.ZoneName, SavedAt: status.SavedAt, CanChange: status.CanChange})
}
