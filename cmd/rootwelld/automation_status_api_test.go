package main

import (
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

func TestAutomationOverviewGateNoNewAuthority(t *testing.T) {
	g, path := testGate(t)
	setup := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil))
	route := "/api/automation/status"
	if w := accountCall(g, "POST", route, accountStatusInput, setup, "http://"+localHost, true); w.Code != 403 {
		t.Fatal("setup can read automation")
	}
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	for _, tc := range []struct {
		method, body, origin string
		cookie               *http.Cookie
		header               bool
		code                 int
	}{
		{"POST", accountStatusInput, "http://" + localHost, nil, true, 401},
		{"GET", accountStatusInput, "http://" + localHost, cookie, true, 405},
		{"POST", accountStatusInput, "http://evil.invalid", cookie, true, 403},
		{"POST", accountStatusInput, "http://" + localHost, cookie, false, 403},
		{"POST", `{"provider":"letsencrypt-staging","confirm":true}`, "http://" + localHost, cookie, true, 400},
		{"POST", `{"provider":"letsencrypt-staging","password":"secret-sentinel"}`, "http://" + localHost, cookie, true, 400},
		{"POST", `{"provider":"letsencrypt-staging","provider":"letsencrypt-staging"}`, "http://" + localHost, cookie, true, 400},
	} {
		w := accountCall(g, tc.method, route, tc.body, tc.cookie, tc.origin, tc.header)
		if w.Code != tc.code || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("bad status gate", w.Code, tc.code)
		}
	}
	if runtime.GOOS != "linux" {
		if w := accountCall(g, "POST", route, accountStatusInput, cookie, "http://"+localHost, true); w.Code != 503 {
			t.Fatal("native custody enabled")
		}
	}
	for _, asset := range []string{"/automation", "/automation-status.js"} {
		if w := call(g, "GET", asset, "", cookie); w.Code != 200 {
			t.Fatal("ready asset unavailable")
		}
		if w := call(g, "GET", asset, "", nil); w.Code != 303 {
			t.Fatal("anonymous asset exposed")
		}
	}
}
