package main

import (
	"bytes"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

const dnsStatusInput = `{"provider":"cloudflare"}`
const dnsSaveInput = `{"provider":"cloudflare","confirm":true,"expected_generation":1,"password":"` + nextTestPassword + `","zone_id":"0123456789abcdef0123456789abcdef","zone_name":"example.com","token":"synthetic-only-credential-not-a-real-token-1234567890"}`
const dnsRemoveInput = `{"provider":"cloudflare","confirm":true,"expected_generation":2,"password":"` + nextTestPassword + `"}`

func TestCloudflareConfigurationRequestStrictShapesNoPartialSecrets(t *testing.T) {
	parse := func(body, mode string, want bool) {
		t.Helper()
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		input, ok := readDNSConfigInput(httptest.NewRecorder(), r, mode)
		defer clear(input.Token)
		if ok != want || !ok && (input.Password != "" || input.Expected != 0 || len(input.Token) != 0) {
			t.Fatal("DNS parser wrong or partial secret result")
		}
	}
	parse(dnsStatusInput, "status", true)
	parse(dnsSaveInput, "save", true)
	parse(dnsRemoveInput, "remove", true)
	parse(dnsSaveInput, "remove", false)
	parse(dnsSaveInput, "status", false)
	parse(dnsStatusInput, "save", false)
	parse(dnsRemoveInput, "save", false)
	for _, body := range []string{"null", "[]", dnsSaveInput + "{}", string([]byte{0xff}), strings.Repeat(" ", 4097),
		strings.Replace(dnsSaveInput, `"confirm":true`, `"confirm":false`, 1), strings.Replace(dnsSaveInput, `"confirm":true`, `"confirm":null`, 1),
		strings.Replace(dnsSaveInput, `"expected_generation":1`, `"expected_generation":null`, 1), strings.Replace(dnsSaveInput, `"expected_generation":1`, `"expected_generation":1.0`, 1),
		strings.Replace(dnsSaveInput, `"expected_generation":1`, `"expected_generation":0`, 1), strings.Replace(dnsSaveInput, `"expected_generation":1`, `"expected_generation":1000001`, 1),
		strings.Replace(dnsSaveInput, `"password":"`+nextTestPassword+`"`, `"password":null`, 1), strings.Replace(dnsSaveInput, `"password":"`+nextTestPassword+`"`, `"password":""`, 1),
		strings.Replace(dnsSaveInput, `"provider":"cloudflare"`, `"Provider":"cloudflare"`, 1), strings.Replace(dnsSaveInput, `"provider":"cloudflare"`, `"provider":"other"`, 1),
		strings.Replace(dnsSaveInput, `"zone_name":"example.com"`, `"zone_name":"*.example.com"`, 1), strings.Replace(dnsSaveInput, `"zone_name":"example.com"`, `"zone_name":null`, 1),
		strings.Replace(dnsSaveInput, `"zone_id":"0123456789abcdef0123456789abcdef"`, `"zone_id":"../secret-sentinel"`, 1),
		strings.Replace(dnsSaveInput, `"token":"synthetic-only-credential-not-a-real-token-1234567890"`, `"token":null`, 1),
	} {
		parse(body, "save", false)
	}
	for _, extra := range []string{`"provider":"cloudflare"`, `"token":"duplicate-secret-sentinel"`, `"zone_name":"other.com"`, `"Token":"secret-sentinel"`, `"url":"https://secret-sentinel.invalid"`, `"global_api_key":"secret-sentinel"`, `"token_verified":true`} {
		parse(strings.TrimSuffix(dnsSaveInput, "}")+","+extra+"}", "save", false)
	}
}

func TestCloudflareConfigurationGateReadyOriginAndNativeRefusal(t *testing.T) {
	g, path := testGate(t)
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	for _, tc := range []struct{ route, body string }{{"status", dnsStatusInput}, {"save", dnsSaveInput}, {"remove", dnsRemoveInput}} {
		route := "/api/dns/cloudflare/" + tc.route
		for _, req := range []struct {
			method, origin string
			header         bool
			anonymous      bool
			want           int
		}{
			{"POST", "http://" + localHost, true, true, 401}, {"GET", "http://" + localHost, true, false, 405}, {"POST", "http://evil.invalid", true, false, 403}, {"POST", "http://" + localHost, false, false, 403},
		} {
			c := cookie
			if req.anonymous {
				c = nil
			}
			w := accountCall(g, req.method, route, tc.body, c, req.origin, req.header)
			if w.Code != req.want {
				t.Fatal("DNS configuration gate bypassed")
			}
		}
		if w := accountCall(g, "POST", route+"?token=secret-sentinel", tc.body, cookie, "http://"+localHost, true); w.Code != 400 || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("query accepted or reflected")
		}
		if runtime.GOOS != "linux" {
			if w := accountCall(g, "POST", route, tc.body, cookie, "http://"+localHost, true); w.Code != 503 {
				t.Fatal("native credential custody accepted")
			}
		}
	}
	if w := call(g, "GET", "/cloudflare-config.js", "", cookie); w.Code != 200 || !strings.Contains(w.Body.String(), "/api/dns/cloudflare/") {
		t.Fatal("ready UI script unavailable")
	}
	setupGate, _ := testGate(t)
	setup := sessionCookie(t, call(setupGate, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil))
	if w := accountCall(setupGate, "POST", "/api/dns/cloudflare/save", dnsSaveInput, setup, "http://"+localHost, true); w.Code != 403 {
		t.Fatal("setup credential save accepted")
	}
	if w := call(setupGate, "GET", "/cloudflare-config.js", "", setup); w.Code != 303 {
		t.Fatal("setup exposed script")
	}
}

func FuzzCloudflareConfigurationRequest(f *testing.F) {
	f.Add([]byte(dnsSaveInput), "save")
	f.Add([]byte(dnsRemoveInput), "remove")
	f.Add([]byte(dnsStatusInput), "status")
	f.Fuzz(func(t *testing.T, data []byte, mode string) {
		if len(data) > 8192 {
			t.Skip()
		}
		r := httptest.NewRequest("POST", "/", bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		input, ok := readDNSConfigInput(httptest.NewRecorder(), r, mode)
		defer clear(input.Token)
		if !ok && (input.Password != "" || input.Expected != 0 || len(input.Token) != 0) {
			t.Fatal("partial credential result")
		}
		if ok && mode != "status" && (input.Password == "" || input.Expected < 1 || input.Expected > 1000000) {
			t.Fatal("invalid mutation authority")
		}
	})
}
