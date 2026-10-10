package main

import (
	"context"
	"crypto"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

const orderStatusInput = `{"provider":"letsencrypt-staging"}`

func orderRequest(gen string, start bool) string {
	domains := ""
	if start {
		domains = `,"domains":["example.com","*.example.com"]`
	}
	return `{"provider":"letsencrypt-staging","confirm":true,"expected_generation":` + gen + `,"password":"` + nextTestPassword + `"` + domains + `}`
}

func TestManualDNSRequestStrictShapesNeverReturnPartialAuthority(t *testing.T) {
	for mode, valid := range map[string]string{"status": orderStatusInput, "start": orderRequest("4", true), "resume": orderRequest("6", false), "ack": orderRequest("7", false)} {
		parse := func(body string, want bool) {
			t.Helper()
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			input, ok := readOrderInput(httptest.NewRecorder(), r, mode)
			if ok != want || !ok && (input.Password != "" || input.Expected != 0 || input.Names != nil) {
				t.Fatal("unsafe/partial request accepted")
			}
		}
		parse(valid, true)
		for _, bad := range []string{"null", "[]", valid + "{}", string([]byte{0xff}), strings.Repeat(" ", 4097), strings.Replace(valid, "letsencrypt-staging", "production", 1), strings.Replace(valid, "\"provider\":", "\"Provider\":", 1), strings.TrimSuffix(valid, "}") + `,"provider":"letsencrypt-staging"}`, strings.TrimSuffix(valid, "}") + `,"order_url":"http://127.0.0.1"}`, strings.TrimSuffix(valid, "}") + `,"private_key":"sentinel"}`} {
			parse(bad, false)
		}
		if mode != "status" {
			for _, bad := range []string{strings.Replace(valid, `"confirm":true`, `"confirm":false`, 1), strings.Replace(valid, `"confirm":true`, `"confirm":null`, 1), strings.Replace(valid, `"password":"`+nextTestPassword+`"`, `"password":null`, 1), strings.Replace(valid, `"expected_generation":`, `"Expected_generation":`, 1), strings.Replace(valid, `"expected_generation":`+map[string]string{"start": "4", "resume": "6", "ack": "7"}[mode], `"expected_generation":null`, 1)} {
				parse(bad, false)
			}
		}
		if mode == "start" {
			for _, domains := range []string{`null`, `[]`, `["example.com","EXAMPLE.com"]`, `["127.0.0.1"]`, `["internal.local"]`} {
				parse(strings.Replace(valid, `["example.com","*.example.com"]`, domains, 1), false)
			}
		}
	}
}

func TestManualDNSGateRequiresReadyOriginAndNativeRefusal(t *testing.T) {
	g, path := testGate(t)
	calls := 0
	g.orderConnect = func(context.Context, func() bool, crypto.Signer, string, string, []string, func(string) error) (acmeorder.Instructions, error) {
		calls++
		t.Error("unapproved network authority")
		return acmeorder.Instructions{}, nil
	}
	setup := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil))
	for _, mode := range []string{"status", "start", "resume", "ack"} {
		route := "/api/acme/order/" + mode
		if w := accountCall(g, "POST", route, orderStatusInput, setup, "http://"+localHost, true); w.Code != 403 {
			t.Fatal("setup granted order authority")
		}
		if w := call(g, "POST", route, orderStatusInput, nil); w.Code != 401 {
			t.Fatal("anonymous order request accepted")
		}
	}
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	for _, bad := range []struct {
		method, path, origin string
		metadata             bool
	}{{"GET", "/api/acme/order/status", "http://" + localHost, true}, {"POST", "/api/acme/order/status?password=sentinel", "http://" + localHost, true}, {"POST", "/api/acme/order/status", "http://evil.invalid", true}, {"POST", "/api/acme/order/status", "http://" + localHost, false}} {
		w := accountCall(g, bad.method, bad.path, orderStatusInput, cookie, bad.origin, bad.metadata)
		if w.Code == 200 || strings.Contains(w.Body.String(), "sentinel") {
			t.Fatal("unsafe route accepted/reflected")
		}
	}
	if runtime.GOOS != "linux" {
		for _, mode := range []string{"status", "start", "resume", "ack"} {
			input := orderRequest("4", mode == "start")
			if mode == "status" {
				input = orderStatusInput
			}
			if w := accountCall(g, "POST", "/api/acme/order/"+mode, input, cookie, "http://"+localHost, true); w.Code != 503 {
				t.Fatal("native order accepted")
			}
		}
	}
	if w := call(g, "GET", "/acme-order.js", "", cookie); w.Code != 200 || w.Body.Len() == 0 {
		t.Fatal("ready script unavailable")
	}
	if w := call(g, "GET", "/acme-order.js", "", nil); w.Code != 303 {
		t.Fatal("anonymous script exposed")
	}
	if calls != 0 {
		t.Fatal("unapproved network request")
	}
}

func FuzzManualDNSRequest(f *testing.F) {
	f.Add([]byte(orderStatusInput))
	f.Add([]byte(orderRequest("4", true)))
	f.Add([]byte(orderRequest("6", false)))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 4097 {
			return
		}
		for _, mode := range []string{"status", "start", "resume", "ack"} {
			r := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
			r.Header.Set("Content-Type", "application/json")
			input, ok := readOrderInput(httptest.NewRecorder(), r, mode)
			if !ok && (input.Password != "" || input.Expected != 0 || input.Names != nil) {
				t.Fatal("partial authority")
			}
		}
	})
}
