package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/websitechain"
)

const websiteConsent = `{"target":"website.example.org","confirm":true}`

func TestWebsiteEmbeddedExamplesAreSyntheticAndBounded(t *testing.T) {
	body, err := authAssets.ReadFile("auth/website-examples.json")
	if err != nil || len(body) == 0 || len(body) > 98304 || bytes.Contains(body, []byte("PRIVATE KEY")) {
		t.Fatal("public example asset missing or unsafe")
	}
	var fixture struct {
		Synthetic bool                           `json:"synthetic"`
		Examples  map[string]websitechain.Report `json:"examples"`
	}
	if json.Unmarshal(body, &fixture) != nil || !fixture.Synthetic || len(fixture.Examples) != 3 {
		t.Fatal("example wrapper invalid")
	}
	for name, r := range fixture.Examples {
		if r.Schema != websitechain.Schema || r.Revocation != "not-checked" || !strings.Contains(r.TrustSource, "Synthetic") || !strings.Contains(r.Address, "example only") {
			t.Fatal("example implies live observation")
		}
		if name == "valid" {
			if r.State != "verified" || !r.Trusted || len(r.Path) != 3 || r.Path[2].Sent {
				t.Fatal("healthy example lost local-root semantics")
			}
		} else if (name != "missing" && name != "wrong") || r.State != "failed" || r.Trusted {
			t.Fatal("broken example implies success")
		}
	}
}

func TestWebsiteConsentExactAndNoSecrets(t *testing.T) {
	for _, body := range []string{websiteConsent, `{"confirm":true,"target":"https://website.example.org:443/"}`, `{"target":"website.example.org","confirm":null}`, `{"target":"website.example.org","confirm":false}`, `{"target":"website.example.org"}`, `{"Target":"website.example.org","confirm":true}`, websiteConsent + `{}`, `{"target":"website.example.org","confirm":true,"confirm":true}`, `{"target":"website.example.org","confirm":true,"password":"sentinel"}`, `{"target":"http://169.254.169.254","confirm":true}`, `{"target":null,"confirm":true}`, strings.Repeat(" ", 1025), "null", string([]byte{0xff})} {
		r := httptest.NewRequest("POST", "/api/website-check", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		host, ok := readWebsiteConsent(httptest.NewRecorder(), r)
		want := body == websiteConsent || body == `{"confirm":true,"target":"https://website.example.org:443/"}`
		if ok != want || (ok && host != "website.example.org") {
			t.Fatalf("unsafe consent: %q %q %v", body, host, ok)
		}
	}
}

func TestWebsiteComparisonCannotUploadCertificatesOrTrustToAPI(t *testing.T) {
	for _, field := range []string{"certificate", "expected_certificate", "fingerprint", "private_key", "trust_bundle"} {
		body := `{"target":"website.example.org","confirm":true,"` + field + `":"private-input-sentinel"}`
		r := httptest.NewRequest("POST", "/api/website-check", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if _, ok := readWebsiteConsent(httptest.NewRecorder(), r); ok {
			t.Fatal("file/trust comparison input entered the server API")
		}
	}
}

func TestWebsiteGateNeedsReadyOriginConsentAndThrottleAndWritesNothing(t *testing.T) {
	g, cookie, path := readyDirectoryGate(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	g.websiteCheck = func(ctx context.Context, host string, permit func() bool) (websitechain.Report, error) {
		calls++
		if !permit() || host != "website.example.org" {
			t.Fatal("wrong authority")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 8*time.Second {
			t.Fatal("no total deadline")
		}
		return websitechain.Report{Schema: websitechain.Schema, State: "failed"}, nil
	}
	for _, bad := range []struct {
		method, body, origin string
		cookie               *http.Cookie
		header               bool
	}{
		{"POST", websiteConsent, "http://" + localHost, nil, true},
		{"GET", websiteConsent, "http://" + localHost, cookie, true},
		{"POST", websiteConsent, "http://evil.invalid", cookie, true},
		{"POST", websiteConsent, "http://" + localHost, cookie, false},
		{"POST", `{"target":"website.example.org","confirm":false}`, "http://" + localHost, cookie, true},
	} {
		w := acmeCall(g, bad.method, "/api/website-check", bad.body, bad.cookie, bad.origin, bad.header)
		if w.Code < 400 || calls != 0 {
			t.Fatal("unauthorized network capability")
		}
	}
	for _, route := range []string{"/website-check", "/website-check.js", "/website-expected.js", "/website-check.css", "/website-examples.json"} {
		if w := call(g, "GET", route, "", nil); w.Code != 303 {
			t.Fatal("anonymous asset exposed")
		}
		if w := call(g, "GET", route, "", cookie); w.Code != 200 {
			t.Fatalf("ready asset missing %s: %d", route, w.Code)
		}
	}
	w := acmeCall(g, "POST", "/api/website-check", websiteConsent, cookie, "http://"+localHost, true)
	if w.Code != 200 || calls != 1 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), `"state":"failed"`) {
		t.Fatal("diagnostic failure not preserved")
	}
	if w := acmeCall(g, "POST", "/api/website-check", websiteConsent, cookie, "http://"+localHost, true); w.Code != 429 || calls != 1 {
		t.Fatal("repeat not bounded")
	}
	base := g.now()
	g.now = func() time.Time { return base.Add(31 * time.Second) }
	g.websiteBusy = true
	if w := acmeCall(g, "POST", "/api/website-check", websiteConsent, cookie, "http://"+localHost, true); w.Code != 429 || calls != 1 {
		t.Fatal("concurrent check accepted")
	}
	g.websiteBusy = false
	g.websiteCheck = func(context.Context, string, func() bool) (websitechain.Report, error) {
		return websitechain.Report{}, errors.New("private-sentinel")
	}
	w = acmeCall(g, "POST", "/api/website-check", websiteConsent, cookie, "http://"+localHost, true)
	if w.Code != 502 || strings.Contains(w.Body.String(), "sentinel") {
		t.Fatal("raw peer error reflected")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read-only check modified access image")
	}
}

func TestWebsiteSetupAndLateSessionCannotPublish(t *testing.T) {
	g, _ := testGate(t)
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil))
	g.websiteCheck = func(context.Context, string, func() bool) (websitechain.Report, error) {
		t.Fatal("setup authorized network")
		return websitechain.Report{}, nil
	}
	if w := acmeCall(g, "POST", "/api/website-check", websiteConsent, cookie, "http://"+localHost, true); w.Code != 403 {
		t.Fatal("setup accepted")
	}
	g, cookie, _ = readyDirectoryGate(t)
	g.websiteCheck = func(_ context.Context, _ string, permit func() bool) (websitechain.Report, error) {
		if !permit() {
			t.Fatal("initial permit refused")
		}
		call(g, "DELETE", "/api/session", "", cookie)
		if permit() {
			t.Fatal("revoked authority retained")
		}
		return websitechain.Report{Schema: websitechain.Schema, Hostname: "must-not-publish"}, nil
	}
	w := acmeCall(g, "POST", "/api/website-check", websiteConsent, cookie, "http://"+localHost, true)
	if w.Code != 401 || strings.Contains(w.Body.String(), "must-not-publish") {
		t.Fatal("late result published")
	}
}

func FuzzWebsiteConsent(f *testing.F) {
	f.Add(websiteConsent)
	f.Add(`{"target":"https://127.0.0.1","confirm":true}`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 2048 {
			return
		}
		r := httptest.NewRequest("POST", "/api/website-check", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		host, ok := readWebsiteConsent(httptest.NewRecorder(), r)
		if ok && (host == "" || strings.ContainsAny(host, "/:@?#")) {
			t.Fatal("unsafe destination admitted")
		}
	})
}
