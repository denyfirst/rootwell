package acmestaging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/dnsrecord"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

const cloudflareHost = "api.cloudflare.com"
const cloudflareOrigin = "https://" + cloudflareHost + "/client/v4"

var errDNS = errors.New("DNS operation outcome not confirmed")

type dnsRecordScope = dnsrecord.Scope
type dnsRecordState = dnsrecord.State
type dnsCommit func(dnsRecordState) error

// CloudflareTXT is called only inside the reviewed writer-lock/lease boundary.
// The HTTP user cannot provide a scope, token, state or checkpoint callback.
func CloudflareTXT(ctx context.Context, permit func() bool, token []byte, scope dnsrecord.Scope, saved dnsrecord.State, cleanup, readOnly bool, commit func(dnsrecord.State) error) (dnsrecord.State, error) {
	if !Available() {
		return dnsrecord.State{}, errDNS
	}
	return cloudflareRecord(ctx, permit, liveDependencies(), string(token), scope, saved, cleanup, readOnly, commit)
}

func dnsID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func dnsToken(value string) bool {
	if len(value) < 40 || len(value) > 256 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func validDNSScope(s dnsRecordScope) bool {
	names, ok := acmeorder.Names([]string{s.ZoneName})
	if !ok || len(names) != 1 || names[0] != s.ZoneName || strings.HasPrefix(s.ZoneName, "*.") || !dnsID(s.ZoneID) || !dnsID(s.Owner) || !strings.HasPrefix(s.Name, "_acme-challenge.") {
		return false
	}
	domain := strings.TrimPrefix(s.Name, "_acme-challenge.")
	if names, ok := acmeorder.Names([]string{domain}); !ok || names[0] != domain || strings.HasPrefix(domain, "*.") || domain != s.ZoneName && !strings.HasSuffix(domain, "."+s.ZoneName) {
		return false
	}
	return validOrderToken(s.Value) && len(s.Value) == 43
}
func validDNSState(s dnsRecordState) bool {
	switch s.State {
	case "new", "creating", "borrowed", "deleted":
		return s.ID == ""
	case "created", "deleting":
		return dnsID(s.ID)
	default:
		return false
	}
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Comment string `json:"comment"`
	Proxied bool   `json:"proxied"`
}
type cfSession struct {
	ctx       context.Context
	permit    func() bool
	transport *http.Transport
	token     string
	calls     int
}

type cfZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Type   string `json:"type"`
}
type cfDelete struct {
	ID string `json:"id"`
}

// Known security-relevant field aliases are refused instead of using Go's
// case-insensitive struct matching. Bounded unknown extension fields are ignored.
func cfFields(raw []byte, known ...string) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, false
	}
	for field := range fields {
		for _, name := range known {
			if field != name && strings.EqualFold(field, name) {
				return nil, false
			}
		}
	}
	return fields, true
}
func cfString(fields map[string]json.RawMessage, name string) (string, bool) {
	var s *string
	err := json.Unmarshal(fields[name], &s)
	if err != nil || s == nil {
		return "", false
	}
	return *s, true
}
func cfDecodeRecord(raw []byte) (cfRecord, bool) {
	fields, ok := cfFields(raw, "id", "type", "name", "content", "comment", "proxied")
	if !ok {
		return cfRecord{}, false
	}
	var r cfRecord
	var a, b, c, d bool
	r.ID, a = cfString(fields, "id")
	r.Type, b = cfString(fields, "type")
	r.Name, c = cfString(fields, "name")
	r.Content, d = cfString(fields, "content")
	var proxied *bool
	if !a || !b || !c || !d || json.Unmarshal(fields["proxied"], &proxied) != nil || proxied == nil {
		return cfRecord{}, false
	}
	r.Proxied = *proxied
	if comment, exists := fields["comment"]; exists && string(comment) != "null" {
		var valid bool
		r.Comment, valid = cfString(fields, "comment")
		if !valid {
			return cfRecord{}, false
		}
	}
	return r, true
}

func (c *cfSession) fetch(method, path string, input any, output any) error {
	if c.ctx.Err() != nil || c.permit == nil || !c.permit() || c.calls >= 3 || !strings.HasPrefix(path, "/zones/") {
		return errDNS
	}
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil || len(body) > 2048 {
			return errDNS
		}
		defer clear(body)
	}
	r, err := http.NewRequestWithContext(c.ctx, method, cloudflareOrigin+path, bytes.NewReader(body))
	if err != nil {
		return errDNS
	}
	r.GetBody = nil // disallow even transport replay of a mutable POST/DELETE
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("Accept", "application/json")
	if input != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	c.calls++
	response, err := c.transport.RoundTrip(r)
	r.Header.Del("Authorization")
	if err != nil {
		return errDNS
	}
	defer response.Body.Close()
	if !c.permit() || c.ctx.Err() != nil {
		return errDNS
	}
	if response.StatusCode == 429 || response.StatusCode == 503 {
		return &providerretry.Failure{Hint: providerretry.RetryAfter(response.Header.Values("Retry-After"), time.Now().UTC())}
	}
	if response.StatusCode == 404 && method == http.MethodGet {
		return errDNSMissing
	}
	media, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8") || response.StatusCode != 200 || response.ContentLength > maxBody || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return errDNS
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	defer clear(raw)
	if err != nil || !strictObject(raw) || !c.permit() || c.ctx.Err() != nil {
		return errDNS
	}
	var envelope struct {
		Success bool              `json:"success"`
		Result  json.RawMessage   `json:"result"`
		Errors  []json.RawMessage `json:"errors"`
	}
	// result_info uses snake_case; parse it explicitly instead of guessing or
	// treating missing pagination as proof the filtered collection is complete.
	fields, valid := cfFields(raw, "success", "result", "errors", "messages", "result_info")
	if !valid || json.Unmarshal(raw, &envelope) != nil || !envelope.Success || envelope.Errors == nil || len(envelope.Errors) != 0 {
		return errDNS
	}
	if method == http.MethodGet && strings.Contains(path, "?") {
		var info struct {
			Page       int `json:"page"`
			TotalPages int `json:"total_pages"`
			Count      int `json:"count"`
			TotalCount int `json:"total_count"`
		}
		if _, ok := cfFields(fields["result_info"], "page", "total_pages", "count", "total_count", "per_page"); !ok {
			return errDNS
		}
		infoFields, _ := cfFields(fields["result_info"])
		for _, name := range []string{"page", "total_pages", "count", "total_count"} {
			var value *int
			if json.Unmarshal(infoFields[name], &value) != nil || value == nil {
				return errDNS
			}
		}
		if json.Unmarshal(fields["result_info"], &info) != nil || info.Page != 1 || (info.TotalPages != 1 && !(info.TotalPages == 0 && info.Count == 0)) || info.Count < 0 || info.Count > 100 || info.TotalCount != info.Count {
			return errDNS
		}
		var records []json.RawMessage
		if json.Unmarshal(envelope.Result, &records) != nil || records == nil || len(records) != info.Count {
			return errDNS
		}
	}
	switch target := output.(type) {
	case *cfRecord:
		r, ok := cfDecodeRecord(envelope.Result)
		if !ok {
			return errDNS
		}
		*target = r
	case *[]cfRecord:
		var raws []json.RawMessage
		if json.Unmarshal(envelope.Result, &raws) != nil || raws == nil {
			return errDNS
		}
		records := make([]cfRecord, 0, len(raws))
		for _, raw := range raws {
			r, ok := cfDecodeRecord(raw)
			if !ok {
				return errDNS
			}
			records = append(records, r)
		}
		*target = records
	case *cfZone:
		f, ok := cfFields(envelope.Result, "id", "name", "status", "type")
		if !ok {
			return errDNS
		}
		var a, b, c, d bool
		target.ID, a = cfString(f, "id")
		target.Name, b = cfString(f, "name")
		target.Status, c = cfString(f, "status")
		target.Type, d = cfString(f, "type")
		if !a || !b || !c || !d {
			return errDNS
		}
	case *cfDelete:
		f, ok := cfFields(envelope.Result, "id")
		if !ok {
			return errDNS
		}
		var a bool
		target.ID, a = cfString(f, "id")
		if !a {
			return errDNS
		}
	default:
		return errDNS
	}
	return nil
}

var errDNSMissing = errors.New("DNS record no longer present")

func (c *cfSession) zone(s dnsRecordScope) error {
	var zone cfZone
	if err := c.fetch(http.MethodGet, "/zones/"+s.ZoneID, nil, &zone); err != nil {
		return err
	}
	if zone.ID != s.ZoneID || zone.Name != s.ZoneName || zone.Status != "active" || zone.Type != "full" {
		return errDNS
	}
	return nil
}
func (c *cfSession) matching(s dnsRecordScope) ([]cfRecord, error) {
	q := url.Values{"type": {"TXT"}, "name.exact": {s.Name}, "content.exact": {s.Value}, "per_page": {"100"}, "page": {"1"}}
	var records []cfRecord
	if err := c.fetch(http.MethodGet, "/zones/"+s.ZoneID+"/dns_records?"+q.Encode(), nil, &records); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, r := range records {
		if !dnsID(r.ID) || r.Type != "TXT" || r.Name != s.Name || r.Content != s.Value || r.Proxied || seen[r.ID] {
			return nil, errDNS
		}
		seen[r.ID] = true
	}
	if len(records) > 1 {
		return nil, errDNS
	} // ambiguous duplicate never guessed/pruned
	return records, nil
}
func owns(r cfRecord, s dnsRecordScope, id string) bool {
	return r.ID == id && dnsID(id) && r.Type == "TXT" && r.Name == s.Name && r.Content == s.Value && !r.Proxied && r.Comment == "rootwell-acme-v1-"+s.Owner
}

// Each call performs at most one mutation. Intent must commit BEFORE sending it;
// lost response leaves creating/deleting. Reconciliation is GET-only, never a
// fallback POST, no silent overwrite, no automatic retry or cleanup of borrowed.
func cloudflareRecord(parent context.Context, permit func() bool, deps dependencies, token string, scope dnsRecordScope, saved dnsRecordState, cleanup, readOnly bool, commit dnsCommit) (dnsRecordState, error) {
	if !validDNSScope(scope) || !validDNSState(saved) || !dnsToken(token) || permit == nil || !permit() || (!readOnly && commit == nil) || cleanup && saved.State != "created" && saved.State != "deleting" || cleanup && saved.State == "deleting" && !readOnly || !cleanup && saved.State != "new" && saved.State != "creating" {
		return dnsRecordState{}, errDNS
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	allowed := func() bool { return ctx.Err() == nil && permit() }
	transport := pinnedTransportTo(ctx, allowed, deps, cloudflareHost)
	defer transport.CloseIdleConnections()
	c := cfSession{ctx: ctx, permit: allowed, transport: transport, token: token}
	defer func() { c.token = "" }()
	if err := c.zone(scope); err != nil {
		return dnsRecordState{}, err
	}
	if cleanup {
		return c.cleanup(scope, saved, readOnly, commit)
	}
	records, err := c.matching(scope)
	if err != nil {
		return dnsRecordState{}, err
	}
	if len(records) == 1 {
		if saved.State == "creating" {
			if !owns(records[0], scope, records[0].ID) {
				return dnsRecordState{}, errDNS
			}
			return dnsRecordState{State: "created", ID: records[0].ID}, nil
		}
		if records[0].Comment == "rootwell-acme-v1-"+scope.Owner {
			return dnsRecordState{}, errDNS
		}
		return dnsRecordState{State: "borrowed"}, nil // existing record NEVER cleanup-owned
	}
	if readOnly || saved.State == "creating" {
		return saved, nil
	}
	if !allowed() || commit(dnsRecordState{State: "creating"}) != nil || !allowed() {
		return dnsRecordState{}, errDNS
	}
	input := struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
		Comment string `json:"comment"`
		Proxied bool   `json:"proxied"`
	}{"TXT", scope.Name, scope.Value, 60, "rootwell-acme-v1-" + scope.Owner, false}
	var created cfRecord
	if err := c.fetch(http.MethodPost, "/zones/"+scope.ZoneID+"/dns_records", input, &created); err != nil {
		return dnsRecordState{}, err
	}
	if !owns(created, scope, created.ID) || !allowed() {
		return dnsRecordState{}, errDNS
	}
	return dnsRecordState{State: "created", ID: created.ID}, nil
}
func (c *cfSession) cleanup(s dnsRecordScope, saved dnsRecordState, readOnly bool, commit dnsCommit) (dnsRecordState, error) {
	var record cfRecord
	path := "/zones/" + s.ZoneID + "/dns_records/" + saved.ID
	err := c.fetch(http.MethodGet, path, nil, &record)
	if errors.Is(err, errDNSMissing) {
		// A bare 404 is not absence evidence. Confirm the bounded, complete
		// filtered list also lacks this exact owned record; never delete another.
		records, listErr := c.matching(s)
		if listErr != nil {
			return dnsRecordState{}, listErr
		}
		for _, r := range records {
			if r.ID == saved.ID {
				return dnsRecordState{}, errDNS
			}
		}
		return dnsRecordState{State: "deleted"}, nil
	}
	if err != nil {
		return dnsRecordState{}, err
	}
	if !owns(record, s, saved.ID) {
		return dnsRecordState{}, errDNS
	}
	if readOnly {
		return saved, nil
	}
	if !c.permit() || commit(dnsRecordState{State: "deleting", ID: saved.ID}) != nil || !c.permit() {
		return dnsRecordState{}, errDNS
	}
	var result cfDelete
	if err := c.fetch(http.MethodDelete, path, nil, &result); err != nil {
		return dnsRecordState{}, err
	}
	if result.ID != saved.ID {
		return dnsRecordState{}, errDNS
	}
	return dnsRecordState{State: "deleted"}, nil
}
