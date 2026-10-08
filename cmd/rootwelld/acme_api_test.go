package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

const validACMEPlan = `{"provider":"letsencrypt-staging","challenge":"dns-01","domains":["EXAMPLE.com","*.example.com"]}`

func TestACMEPlanJSONIsBoundedStrictAndSecretFree(t *testing.T) {
	parse := func(body string, expected bool) {
		t.Helper()
		r := httptest.NewRequest("POST", "/api/acme/plan", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		_, ok := readACMEPlan(w, r)
		if ok != expected || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("parser result wrong or reflected input")
		}
	}
	parse(validACMEPlan, true)
	for _, body := range []string{"null", "[]", validACMEPlan + "{}", strings.Repeat(" ", 16*1024+1), string([]byte{0xff}), strings.Replace(validACMEPlan, `"domains":["EXAMPLE.com","*.example.com"]`, `"domains":null`, 1), strings.Replace(validACMEPlan, `"domains":["EXAMPLE.com","*.example.com"]`, `"domains":[null]`, 1), strings.Replace(validACMEPlan, `"provider":"letsencrypt-staging"`, `"provider":null`, 1), strings.TrimSuffix(validACMEPlan, "}") + `,"provider":"letsencrypt-staging"}`, strings.TrimSuffix(validACMEPlan, "}") + `,"password":"secret-sentinel"}`, strings.TrimSuffix(validACMEPlan, "}") + `,"directory":"https://secret-sentinel.invalid"}`, strings.TrimSuffix(validACMEPlan, "}") + `,"network_enabled":true}`} {
		parse(body, false)
	}
	for _, extra := range []string{`"private_key":"secret-sentinel"`, `"email":"secret-sentinel"`, `"terms_agreed":true`, `"dns_token":"secret-sentinel"`} {
		parse(strings.TrimSuffix(validACMEPlan, "}")+","+extra+"}", false)
	}
}

type refuseACMETransport struct{}

type acmeReadHook struct {
	io.Reader
	onRead func()
}

func (r *acmeReadHook) Read(p []byte) (int, error) {
	if r.onRead != nil {
		r.onRead()
		r.onRead = nil
	}
	return r.Reader.Read(p)
}

func FuzzACMEPlanRequestJSON(f *testing.F) {
	f.Add([]byte(validACMEPlan))
	f.Add([]byte(`{"provider":null,"password":"secret-sentinel"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32<<10 {
			t.Skip()
		}
		r := httptest.NewRequest("POST", "/api/acme/plan", bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		plan, ok := readACMEPlan(w, r)
		if ok && (plan.CanIssue || plan.AccountCreated || plan.NetworkEnabled || plan.Saved || len(plan.Domains) == 0 || len(plan.Domains) > 32) {
			t.Fatal("parser granted capability or invalid domain count")
		}
		if !ok && (plan.Schema != "" || len(plan.Domains) != 0 || w.Code < 400) {
			t.Fatal("partial plan on refusal")
		}
	})
}

func (refuseACMETransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("setup must not connect to a CA")
}

func acmeCall(g *gate, method, route, body string, cookie *http.Cookie, origin string, header bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+localHost+route, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	if header {
		r.Header.Set("X-Rootwell-Request", "1")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func TestACMEPlanGateHasNoCAOrPersistenceCapability(t *testing.T) {
	g, path := testGate(t)
	priorTransport := http.DefaultTransport
	http.DefaultTransport = refuseACMETransport{}
	t.Cleanup(func() { http.DefaultTransport = priorTransport })
	for _, asset := range []string{"/automation", "/acme-setup.js"} {
		if w := call(g, "GET", asset, "", nil); w.Code != 303 || w.Header().Get("Location") != "/login" {
			t.Fatal("anonymous asset exposed")
		}
	}
	if w := call(g, "POST", "/api/acme/plan", validACMEPlan, nil); w.Code != 401 {
		t.Fatal("anonymous setup accepted")
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil))
	if w := call(g, "POST", "/api/acme/plan", validACMEPlan, cookie); w.Code != 403 {
		t.Fatal("setup-only session accepted")
	}
	if w := call(g, "GET", "/automation", "", cookie); w.Code != 303 || w.Header().Get("Location") != "/setup" {
		t.Fatal("setup-only page exposed")
	}
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	cookie = sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, asset := range []string{"/automation", "/acme-setup.js"} {
		if w := call(g, "GET", asset, "", cookie); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("ready asset refused")
		}
	}
	w := acmeCall(g, "POST", "/api/acme/plan", validACMEPlan, cookie, "http://"+localHost, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"can_issue":false`) || !strings.Contains(w.Body.String(), `"account_created":false`) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("valid local setup failed or enabled issuance")
	}
	for _, bad := range []struct {
		method, route, origin string
		header                bool
	}{{"POST", "/api/acme/plan", "http://evil.invalid", true}, {"POST", "/api/acme/plan", "http://" + localHost, false}, {"GET", "/api/acme/plan", "", true}, {"POST", "/api/acme/plan?directory=x", "http://" + localHost, true}} {
		if w := acmeCall(g, bad.method, bad.route, validACMEPlan, cookie, bad.origin, bad.header); w.Code < 400 {
			t.Fatal("forbidden operation accepted")
		}
	}
	// Session validity must be checked after reading too, not only at routing.
	for _, expire := range []bool{false, true} {
		priorNow := g.now
		ctx, cancel := context.WithCancel(context.Background())
		r := httptest.NewRequest("POST", "http://"+localHost+"/api/acme/plan", &acmeReadHook{Reader: strings.NewReader(validACMEPlan), onRead: func() {
			if expire {
				g.now = func() time.Time { return priorNow().Add(24 * time.Hour) }
			} else {
				cancel()
			}
		}}).WithContext(ctx)
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://"+localHost)
		r.Header.Set("X-Rootwell-Request", "1")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		cancel()
		g.now = priorNow
		if w.Code != 401 || strings.Contains(w.Body.String(), "setup-checked") {
			t.Fatal("late invalid session/context produced a plan")
		}
	}
	// Expiry removes the old session; obtain a fresh one for the logout check.
	cookie = sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("setup modified access image")
	}
	if w := call(g, "DELETE", "/api/session", "", cookie); w.Code != 204 {
		t.Fatal("logout failed")
	}
	if w := acmeCall(g, "POST", "/api/acme/plan", validACMEPlan, cookie, "http://"+localHost, true); w.Code != 401 {
		t.Fatal("logged out setup accepted")
	}
}
