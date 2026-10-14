package acmestaging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/denyfirst/rootwell/internal/providerretry"
)

func cfScope() dnsRecordScope {
	return dnsRecordScope{ZoneID: strings.Repeat("a", 32), ZoneName: "example.com", Name: "_acme-challenge.example.com", Value: strings.Repeat("A", 43), Owner: strings.Repeat("b", 32)}
}

const cfTestToken = "test-only-token-sentinel-0123456789abcdefghijklmnop"

func cfFixtureRecord(s dnsRecordScope) cfRecord {
	return cfRecord{ID: strings.Repeat("c", 32), Type: "TXT", Name: s.Name, Content: s.Value, Comment: "rootwell-acme-v1-" + s.Owner}
}
func cfReply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": value, "errors": []any{}})
}
func cfList(w http.ResponseWriter, records []cfRecord) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": records, "errors": []any{}, "result_info": map[string]any{"page": 1, "total_pages": 1, "count": len(records), "total_count": len(records)}})
}
func cfZoneReply(w http.ResponseWriter, s dnsRecordScope) {
	cfReply(w, cfZone{ID: s.ZoneID, Name: s.ZoneName, Status: "active", Type: "full"})
}

func TestCloudflareTXTIntentBeforeWriteOwnExactRecordAndCleanup(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	scope := cfScope()
	record := cfFixtureRecord(scope)
	var intent dnsRecordState
	var intentMu sync.Mutex
	readIntent := func() dnsRecordState { intentMu.Lock(); defer intentMu.Unlock(); return intent }
	var posts, deletes atomic.Int32
	deps, _ := fakeProvider(t, cloudflareHost, func(w http.ResponseWriter, r *http.Request) {
		if r.Host != cloudflareHost || r.TLS.ServerName != cloudflareHost || r.Header.Get("Authorization") != "Bearer "+cfTestToken || r.Header.Get("Cookie") != "" || r.Header.Get("X-Auth-Key") != "" || r.Header.Get("Accept-Encoding") != "" {
			t.Error("token transport expanded/leaked authority")
		}
		base := "/client/v4/zones/" + scope.ZoneID
		switch {
		case r.Method == "GET" && r.URL.Path == base:
			cfZoneReply(w, scope)
		case r.Method == "GET" && r.URL.Path == base+"/dns_records":
			if r.URL.Query().Get("name.exact") != scope.Name || r.URL.Query().Get("content.exact") != scope.Value || r.URL.Query().Get("type") != "TXT" || r.URL.Query().Get("per_page") != "100" || r.URL.Query().Get("page") != "1" || len(r.URL.Query()) != 5 {
				t.Error("unbounded or unrelated record listing")
			}
			cfList(w, []cfRecord{})
		case r.Method == "POST" && r.URL.Path == base+"/dns_records":
			posts.Add(1)
			if intent := readIntent(); intent.State != "creating" || intent.ID != "" {
				t.Error("POST preceded durable intent")
			}
			body, _ := io.ReadAll(r.Body)
			var input map[string]any
			if json.Unmarshal(body, &input) != nil || len(input) != 6 || input["type"] != "TXT" || input["name"] != scope.Name || input["content"] != scope.Value || input["comment"] != record.Comment || input["ttl"] != float64(60) || input["proxied"] != false || bytes.Contains(body, []byte(cfTestToken)) {
				t.Error("create expanded its exact TXT scope")
			}
			cfReply(w, record)
		case r.Method == "GET" && r.URL.Path == base+"/dns_records/"+record.ID:
			cfReply(w, record)
		case r.Method == "DELETE" && r.URL.Path == base+"/dns_records/"+record.ID:
			deletes.Add(1)
			if readIntent() != (dnsRecordState{State: "deleting", ID: record.ID}) {
				t.Error("DELETE preceded owned intent")
			}
			cfReply(w, cfDelete{ID: record.ID})
		default:
			t.Error("unreviewed outbound request", r.Method, r.URL.Path)
			w.WriteHeader(400)
		}
	})
	commit := func(s dnsRecordState) error { intentMu.Lock(); defer intentMu.Unlock(); intent = s; return nil }
	created, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, dnsRecordState{State: "new"}, false, false, commit)
	if err != nil || created != (dnsRecordState{State: "created", ID: record.ID}) || posts.Load() != 1 || deletes.Load() != 0 {
		t.Fatal("legitimate TXT creation refused", err)
	}
	clean, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, created, true, false, commit)
	if err != nil || clean != (dnsRecordState{State: "deleted"}) || deletes.Load() != 1 {
		t.Fatal("owned TXT cleanup refused", err)
	}
}

func TestCloudflareExistingBorrowedAndUncertainCreateNeverBlindlyRetry(t *testing.T) {
	scope := cfScope()
	record := cfFixtureRecord(scope)
	for _, tc := range []struct {
		state   string
		records []cfRecord
		wanted  dnsRecordState
	}{
		{"new", []cfRecord{{ID: record.ID, Type: "TXT", Name: scope.Name, Content: scope.Value}}, dnsRecordState{State: "borrowed"}},
		{"creating", []cfRecord{record}, dnsRecordState{State: "created", ID: record.ID}},
		{"creating", []cfRecord{}, dnsRecordState{State: "creating"}},
	} {
		deps, _ := fakeProvider(t, cloudflareHost, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Error("reconciliation mutated DNS")
				w.WriteHeader(400)
				return
			}
			if strings.HasSuffix(r.URL.Path, "/dns_records") {
				cfList(w, tc.records)
			} else {
				cfZoneReply(w, scope)
			}
		})
		for _, readOnly := range []bool{false, true} {
			s, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, dnsRecordState{State: tc.state}, false, readOnly, func(dnsRecordState) error { t.Error("unexpected write intent"); return nil })
			if err != nil || s != tc.wanted {
				t.Fatal("borrowed/reconciliation result incorrect", err)
			}
		}
	}
	var intent dnsRecordState
	var calls atomic.Int32
	deps, _ := fakeProvider(t, cloudflareHost, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"success":true,"result":`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/dns_records") {
			cfList(w, []cfRecord{})
		} else {
			cfZoneReply(w, scope)
		}
	})
	commit := func(s dnsRecordState) error { intent = s; return nil }
	if result, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, dnsRecordState{State: "new"}, false, false, commit); err == nil || result != (dnsRecordState{}) || intent.State != "creating" {
		t.Fatal("unknown POST outcome released partial success")
	}
	if _, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, intent, false, false, commit); err != nil || calls.Load() != 1 {
		t.Fatal("lost creation was blindly repeated")
	}
}

func TestCloudflareRefusesForeignChangedAmbiguousAndBareAbsence(t *testing.T) {
	scope := cfScope()
	record := cfFixtureRecord(scope)
	for _, mutate := range []func(*cfRecord){func(r *cfRecord) { r.Comment = "someone else" }, func(r *cfRecord) { r.Content = "other-value" }, func(r *cfRecord) { r.Name = "_acme-challenge.other.example.com" }, func(r *cfRecord) { r.Type = "A" }, func(r *cfRecord) { r.ID = strings.Repeat("d", 32) }, func(r *cfRecord) { r.Proxied = true }} {
		changed := record
		mutate(&changed)
		deps, _ := fakeProvider(t, cloudflareHost, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Error("changed/foreign record deleted")
			}
			if strings.HasSuffix(r.URL.Path, "/"+record.ID) {
				cfReply(w, changed)
			} else {
				cfZoneReply(w, scope)
			}
		})
		if result, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, dnsRecordState{State: "created", ID: record.ID}, true, false, func(dnsRecordState) error { t.Error("foreign deletion intent"); return nil }); err == nil || result != (dnsRecordState{}) {
			t.Fatal("changed/foreign record acquired deletion authority")
		}
	}
	for _, records := range [][]cfRecord{{record, record}, {record, {ID: strings.Repeat("d", 32), Type: "TXT", Name: scope.Name, Content: scope.Value}}} {
		deps, _ := fakeProvider(t, cloudflareHost, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/dns_records") {
				cfList(w, records)
			} else {
				cfZoneReply(w, scope)
			}
		})
		if result, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, dnsRecordState{State: "creating"}, false, true, nil); err == nil || result != (dnsRecordState{}) {
			t.Fatal("ambiguous records guessed")
		}
	}
	deps, _ := fakeProvider(t, cloudflareHost, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/"+record.ID) {
			w.WriteHeader(404)
		} else if strings.HasSuffix(r.URL.Path, "/dns_records") {
			w.WriteHeader(503)
		} else {
			cfZoneReply(w, scope)
		}
	})
	if result, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, dnsRecordState{State: "deleting", ID: record.ID}, true, true, nil); err == nil || result != (dnsRecordState{}) {
		t.Fatal("bare 404 fabricated cleanup success")
	}
}

func TestCloudflareRefusesUnsafeScopePermitCommitTransportAndMalformedResponse(t *testing.T) {
	scope := cfScope()
	noIO := dependencies{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("refused input contacted DNS")
		return nil, errDNS
	}}
	for _, mutate := range []func(*dnsRecordScope){func(s *dnsRecordScope) { s.Name = "_acme-challenge.evil-example.com" }, func(s *dnsRecordScope) { s.Name = "_acme-challenge.WWW.example.com" }, func(s *dnsRecordScope) { s.ZoneID = "../zones" }, func(s *dnsRecordScope) { s.ZoneName = "*.example.com" }, func(s *dnsRecordScope) { s.Value = "secret" }, func(s *dnsRecordScope) { s.Owner = "" }} {
		bad := scope
		mutate(&bad)
		if result, err := cloudflareRecord(context.Background(), func() bool { return true }, noIO, cfTestToken, bad, dnsRecordState{State: "new"}, false, false, func(dnsRecordState) error { return nil }); err == nil || result != (dnsRecordState{}) {
			t.Fatal("unsafe scope accepted")
		}
	}
	for _, token := range []string{"", cfTestToken + "\r\nAuthorization: bad", "global email API key"} {
		if _, err := cloudflareRecord(context.Background(), func() bool { return true }, noIO, token, scope, dnsRecordState{State: "new"}, false, false, func(dnsRecordState) error { return nil }); err == nil {
			t.Fatal("unsafe token accepted")
		}
	}
	if _, err := cloudflareRecord(context.Background(), func() bool { return false }, noIO, cfTestToken, scope, dnsRecordState{State: "new"}, false, false, func(dnsRecordState) error { return nil }); err == nil {
		t.Fatal("revoked permit accepted")
	}
	for _, addresses := range [][]netip.Addr{{netip.MustParseAddr("127.0.0.1")}, {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}} {
		deps := dependencies{lookup: func(context.Context, string, string) ([]netip.Addr, error) { return addresses, nil }, dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("unsafe provider address dialed")
			return nil, errDNS
		}}
		if _, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, dnsRecordState{State: "new"}, false, true, nil); err == nil {
			t.Fatal("unsafe DNS result accepted")
		}
	}
	for _, reply := range []string{`{"Success":true,"result":{},"errors":[]}`, `{"success":true,"success":true,"result":{},"errors":[]}`, `{"success":true,"result":null,"errors":[]}`, `{"success":true,"result":{},"errors":null}`, "secret-sentinel", strings.Repeat("x", maxBody+1)} {
		deps, _ := fakeProvider(t, cloudflareHost, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, reply)
		})
		if result, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, dnsRecordState{State: "new"}, false, true, nil); err == nil || result != (dnsRecordState{}) || strings.Contains(err.Error(), "secret") {
			t.Fatal("malformed response leaked or succeeded")
		}
	}
	deps, _ := fakeProvider(t, cloudflareHost, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("failed intent led to write")
		}
		if strings.HasSuffix(r.URL.Path, "/dns_records") {
			cfList(w, []cfRecord{})
		} else {
			cfZoneReply(w, scope)
		}
	})
	if result, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, scope, dnsRecordState{State: "new"}, false, false, func(dnsRecordState) error { return errDNS }); err == nil || result != (dnsRecordState{}) {
		t.Fatal("failed intent authorized POST")
	}
}

func TestCloudflareRateLimitHintNeverRetriesOrEchoesProviderBody(t *testing.T) {
	for _, headers := range [][]string{{"3600"}, {"1", "2"}, {"bad"}} {
		var calls atomic.Int32
		deps, _ := fakeProvider(t, cloudflareHost, func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			for _, h := range headers {
				w.Header().Add("Retry-After", h)
			}
			w.WriteHeader(429)
			_, _ = io.WriteString(w, "secret-provider-sentinel")
		})
		_, err := cloudflareRecord(context.Background(), func() bool { return true }, deps, cfTestToken, cfScope(), dnsRecordState{State: "new"}, false, true, nil)
		var failure *providerretry.Failure
		if !errors.As(err, &failure) || calls.Load() != 1 || strings.Contains(err.Error(), "sentinel") || failure.Hint.Blocked != (len(headers) > 1 || headers[0] == "bad") {
			t.Fatal("rate limit duplicated traffic or reflected body")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cloudflareRecord(ctx, func() bool { return true }, dependencies{}, cfTestToken, cfScope(), dnsRecordState{State: "new"}, false, true, nil); err == nil {
		t.Fatal("canceled context accepted")
	}
}

func FuzzCloudflareRecordResponse(f *testing.F) {
	f.Add([]byte(`{"id":"bad","type":"TXT","name":"_acme-challenge.example.com","content":"x","proxied":false}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxBody || !strictObject(raw) {
			return
		}
		r, ok := cfDecodeRecord(raw)
		if ok && owns(r, cfScope(), r.ID) && (!dnsID(r.ID) || r.Name != cfScope().Name || r.Content != cfScope().Value) {
			t.Fatal("malformed record acquired ownership")
		}
	})
}
