package main

import (
	"bytes"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

const dnsAddInput = `{"provider":"cloudflare","password":"` + nextTestPassword + `","expected_generation":8,"index":0,"confirm":true}`

func TestDNSOperationStrictRequestNoPartialAuthority(t *testing.T) {
	parse := func(body, mode string, want bool) {
		t.Helper()
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		input, ok := readDNSOperationInput(httptest.NewRecorder(), r, mode)
		if ok != want || !ok && (input.Password != "" || input.Expected != 0) {
			t.Fatal("DNS request parser partial/wrong authority")
		}
	}
	parse(dnsStatusInput, "status", true)
	parse(dnsAddInput, "add", true)
	parse(dnsAddInput, "check", true)
	parse(strings.TrimSuffix(dnsAddInput, "}")+`,"exclusive":true}`, "cleanup", true)
	for _, body := range []string{"null", "[]", dnsAddInput + "{}", string([]byte{0xff}), strings.Repeat(" ", 4097), strings.Replace(dnsAddInput, `"index":0`, `"index":null`, 1), strings.Replace(dnsAddInput, `"index":0`, `"index":-1`, 1), strings.Replace(dnsAddInput, `"index":0`, `"index":8`, 1), strings.Replace(dnsAddInput, `"index":0`, `"index":0.0`, 1), strings.Replace(dnsAddInput, `"confirm":true`, `"confirm":false`, 1), strings.Replace(dnsAddInput, `"confirm":true`, `"confirm":null`, 1), strings.Replace(dnsAddInput, `"password":"`+nextTestPassword+`"`, `"password":null`, 1), strings.Replace(dnsAddInput, `"expected_generation":8`, `"expected_generation":0`, 1), strings.Replace(dnsAddInput, `"expected_generation":8`, `"expected_generation":null`, 1)} {
		parse(body, "add", false)
	}
	for _, extra := range []string{`"index":1`, `"Index":1`, `"record_id":"foreign"`, `"token":"secret-sentinel"`, `"txt":"secret-sentinel"`, `"owner":"secret-sentinel"`, `"state":"created"`, `"exclusive":true`, `"url":"https://secret-sentinel.invalid"`} {
		parse(strings.TrimSuffix(dnsAddInput, "}")+","+extra+"}", "add", false)
	}
	parse(dnsAddInput, "cleanup", false)
	parse(strings.TrimSuffix(dnsAddInput, "}")+`,"exclusive":false}`, "cleanup", false)
	parse(dnsAddInput, "status", false)
	parse(dnsStatusInput, "add", false)
	parse(dnsAddInput, "reset", false)
}

func TestDNSOperationGateOriginSetupAndNativeRefusal(t *testing.T) {
	g, path := testGate(t)
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	for _, mode := range []string{"status", "add", "check", "cleanup"} {
		route := "/api/acme/dns/" + mode
		body := dnsAddInput
		if mode == "status" {
			body = dnsStatusInput
		}
		if mode == "cleanup" {
			body = strings.TrimSuffix(body, "}") + `,"exclusive":true}`
		}
		for _, tc := range []struct {
			method, origin    string
			header, anonymous bool
			want              int
		}{{"POST", "http://" + localHost, true, true, 401}, {"GET", "http://" + localHost, true, false, 405}, {"POST", "http://evil.invalid", true, false, 403}, {"POST", "http://" + localHost, false, false, 403}} {
			c := cookie
			if tc.anonymous {
				c = nil
			}
			w := accountCall(g, tc.method, route, body, c, tc.origin, tc.header)
			if w.Code != tc.want {
				t.Fatal("DNS endpoint gate bypassed", w.Code)
			}
		}
		if w := accountCall(g, "POST", route+"?token=secret-sentinel", body, cookie, "http://"+localHost, true); w.Code != 400 || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("query reflected/accepted")
		}
		if runtime.GOOS != "linux" {
			if w := accountCall(g, "POST", route, body, cookie, "http://"+localHost, true); w.Code != 503 {
				t.Fatal("native DNS operation enabled")
			}
		}
	}
	if w := call(g, "GET", "/dns-operation.js", "", cookie); w.Code != 200 || !strings.Contains(w.Body.String(), "/api/acme/dns/") {
		t.Fatal("ready DNS UI script unavailable")
	}
	setupGate, _ := testGate(t)
	setup := sessionCookie(t, call(setupGate, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil))
	if w := accountCall(setupGate, "POST", "/api/acme/dns/add", dnsAddInput, setup, "http://"+localHost, true); w.Code != 403 {
		t.Fatal("setup session acquired DNS authority")
	}
	if w := call(setupGate, "GET", "/dns-operation.js", "", setup); w.Code != 303 {
		t.Fatal("setup leaked DNS asset")
	}
}

func FuzzDNSOperationRequest(f *testing.F) {
	f.Add([]byte(dnsStatusInput), "status")
	f.Add([]byte(dnsAddInput), "add")
	f.Add([]byte(strings.TrimSuffix(dnsAddInput, "}")+`,"exclusive":true}`), "cleanup")
	f.Fuzz(func(t *testing.T, data []byte, mode string) {
		if len(data) > 8192 {
			t.Skip()
		}
		r := httptest.NewRequest("POST", "/", bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		input, ok := readDNSOperationInput(httptest.NewRecorder(), r, mode)
		if !ok && (input.Password != "" || input.Expected != 0) {
			t.Fatal("partial refused authority")
		}
		if ok && mode != "status" && (input.Index < 0 || input.Index > 7 || input.Expected < 1 || input.Expected > 1000000 || input.Password == "") {
			t.Fatal("invalid accepted authority")
		}
	})
}
