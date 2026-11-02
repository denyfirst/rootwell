package main

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

const productionAccountStatusInput = `{"provider":"letsencrypt-production"}`
const productionAccountPrepareInput = `{"provider":"letsencrypt-production","confirm":true,"expected_generation":1,"password":"` + nextTestPassword + `"}`

func TestProductionAccountParserCannotSelectStagingOrNetworkAuthority(t *testing.T) {
	for _, preparing := range []bool{false, true} {
		body := productionAccountStatusInput
		if preparing {
			body = productionAccountPrepareInput
		}
		for _, tc := range []struct {
			body, provider string
			valid          bool
		}{
			{body, "letsencrypt-production", true}, {body, "letsencrypt-staging", false}, {body, "", false},
			{strings.Replace(body, "letsencrypt-production", "letsencrypt-staging", 1), "letsencrypt-production", false},
			{strings.TrimSuffix(body, "}") + `,"provider":"letsencrypt-production"}`, "letsencrypt-production", false},
			{strings.TrimSuffix(body, "}") + `,"registration_state":"registered"}`, "letsencrypt-production", false},
			{strings.TrimSuffix(body, "}") + `,"directory":"https://secret-sentinel.invalid"}`, "letsencrypt-production", false},
			{strings.TrimSuffix(body, "}") + `,"private_key":"secret-sentinel"}`, "letsencrypt-production", false},
		} {
			r := httptest.NewRequest("POST", "/", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			input, ok := readAccountInputForProvider(httptest.NewRecorder(), r, preparing, tc.provider)
			if ok != tc.valid || !ok && (input.Password != "" || input.Expected != 0) {
				t.Fatal("wrong profile admission or partial secret")
			}
		}
	}
}

func TestProductionAccountGateOwnerOriginSetupAndNativeRefusal(t *testing.T) {
	g, path := testGate(t)
	setupCookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil))
	if w := accountCall(g, "POST", "/api/acme/production-account/status", productionAccountStatusInput, setupCookie, "http://"+localHost, true); w.Code != 403 {
		t.Fatal("setup session reached production custody")
	}
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	for _, route := range []string{"/api/acme/production-account/status", "/api/acme/production-account/prepare"} {
		body := productionAccountStatusInput
		if strings.HasSuffix(route, "prepare") {
			body = productionAccountPrepareInput
		}
		for _, tc := range []struct {
			method, body, origin string
			cookie               *http.Cookie
			header               bool
			code                 int
		}{
			{"POST", body, "http://" + localHost, nil, true, 401},
			{"GET", body, "http://" + localHost, cookie, true, 405},
			{"POST", body, "http://evil.invalid", cookie, true, 403},
			{"POST", body, "http://" + localHost, cookie, false, 403},
			{"POST", strings.Replace(body, "letsencrypt-production", "letsencrypt-staging", 1), "http://" + localHost, cookie, true, 400},
		} {
			w := accountCall(g, tc.method, route, tc.body, tc.cookie, tc.origin, tc.header)
			if w.Code != tc.code || strings.Contains(w.Body.String(), "PRIVATE KEY") {
				t.Fatal("production gate bypass", w.Code)
			}
		}
		if runtime.GOOS != "linux" {
			if w := accountCall(g, "POST", route, body, cookie, "http://"+localHost, true); w.Code != 503 {
				t.Fatal("native custody enabled")
			}
		}
	}
}
