package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

const accountStatusInput = `{"provider":"letsencrypt-staging"}`
const accountPrepareInput = `{"provider":"letsencrypt-staging","confirm":true,"expected_generation":1,"password":"` + nextTestPassword + `"}`

func accountCall(g *gate, method, route, body string, cookie *http.Cookie, origin string, header bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+localHost+route, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
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

func TestAccountRequestStrictShapesNeverAcceptSecretsOrAuthority(t *testing.T) {
	parse := func(body string, prepare, want bool) {
		t.Helper()
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		input, ok := readAccountInput(httptest.NewRecorder(), r, prepare)
		if ok != want || !ok && (input.Password != "" || input.Expected != 0) {
			t.Fatal("account parser wrong or partial secret result")
		}
	}
	parse(accountStatusInput, false, true)
	parse(accountPrepareInput, true, true)
	parse(accountPrepareInput, false, false)
	parse(accountStatusInput, true, false)
	for _, body := range []string{"null", "[]", accountPrepareInput + "{}", string([]byte{0xff}), strings.Repeat(" ", 4097), strings.Replace(accountPrepareInput, `"confirm":true`, `"confirm":false`, 1), strings.Replace(accountPrepareInput, `"confirm":true`, `"confirm":null`, 1), strings.Replace(accountPrepareInput, `"expected_generation":1`, `"expected_generation":null`, 1), strings.Replace(accountPrepareInput, `"expected_generation":1`, `"expected_generation":0`, 1), strings.Replace(accountPrepareInput, `"expected_generation":1`, `"expected_generation":1.0`, 1), strings.Replace(accountPrepareInput, `"expected_generation":1`, `"expected_generation":1000001`, 1), strings.Replace(accountPrepareInput, `"password":"`+nextTestPassword+`"`, `"password":null`, 1), strings.Replace(accountPrepareInput, `"password":"`+nextTestPassword+`"`, `"password":""`, 1), strings.Replace(accountPrepareInput, `"provider":"letsencrypt-staging"`, `"Provider":"letsencrypt-staging"`, 1)} {
		parse(body, true, false)
	}
	for _, extra := range []string{`"provider":"letsencrypt-staging"`, `"private_key":"secret-sentinel"`, `"email":"secret-sentinel"`, `"terms_agreed":true`, `"account_created":true`, `"directory":"https://secret-sentinel.invalid"`, `"domains":["example.com"]`} {
		parse(strings.TrimSuffix(accountPrepareInput, "}")+","+extra+"}", true, false)
	}
}

func TestAccountGateReadyOriginAndNativeRefusal(t *testing.T) {
	g, path := testGate(t)
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	for _, route := range []string{"/api/acme/account/status", "/api/acme/account/prepare"} {
		body := accountStatusInput
		if strings.HasSuffix(route, "prepare") {
			body = accountPrepareInput
		}
		if w := accountCall(g, "POST", route, body, nil, "http://"+localHost, true); w.Code != 401 {
			t.Fatal("anonymous account access")
		}
		if w := accountCall(g, "GET", route, body, cookie, "http://"+localHost, true); w.Code != 405 {
			t.Fatal("GET accepted")
		}
		if w := accountCall(g, "POST", route, body, cookie, "http://evil.invalid", true); w.Code != 403 {
			t.Fatal("cross-origin accepted")
		}
		if w := accountCall(g, "POST", route, body, cookie, "http://"+localHost, false); w.Code != 403 {
			t.Fatal("missing header accepted")
		}
		if w := accountCall(g, "POST", route+"?password=secret-sentinel", body, cookie, "http://"+localHost, true); w.Code != 400 || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("query accepted or reflected")
		}
		if runtime.GOOS != "linux" {
			if w := accountCall(g, "POST", route, body, cookie, "http://"+localHost, true); w.Code != 503 {
				t.Fatal("native custody not refused")
			}
		}
	}
	for _, route := range []string{"/automation", "/acme-account.js"} {
		if w := call(g, "GET", route, "", cookie); w.Code != 200 || len(w.Body.Bytes()) == 0 {
			t.Fatal("ready account asset unavailable")
		}
	}
	setupGate, _ := testGate(t)
	setup := sessionCookie(t, call(setupGate, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil))
	if w := accountCall(setupGate, "POST", "/api/acme/account/prepare", accountPrepareInput, setup, "http://"+localHost, true); w.Code != 403 {
		t.Fatal("setup key preparation")
	}
	if w := call(setupGate, "GET", "/acme-account.js", "", setup); w.Code != 303 {
		t.Fatal("setup exposed script")
	}
}

func FuzzStagingAccountRequest(f *testing.F) {
	f.Add([]byte(accountPrepareInput), true)
	f.Add([]byte(accountStatusInput), false)
	f.Fuzz(func(t *testing.T, data []byte, prepare bool) {
		if len(data) > 8192 {
			t.Skip()
		}
		r := httptest.NewRequest("POST", "/", bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		input, ok := readAccountInput(httptest.NewRecorder(), r, prepare)
		if !ok && (input.Password != "" || input.Expected != 0) {
			t.Fatal("partial secret on refusal")
		}
		if ok && prepare && (input.Password == "" || input.Expected < 1 || input.Expected > 1000000) {
			t.Fatal("invalid preparation authority")
		}
	})
}
