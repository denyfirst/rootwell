package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

type timingRecorder struct {
	*httptest.ResponseRecorder
	readDeadline, writeDeadline time.Time
}

func (w *timingRecorder) SetReadDeadline(at time.Time) error  { w.readDeadline = at; return nil }
func (w *timingRecorder) SetWriteDeadline(at time.Time) error { w.writeDeadline = at; return nil }
func timingCall(g *gate, mode, body string, cookie *http.Cookie) *timingRecorder {
	r := httptest.NewRequest("POST", "http://"+localHost+"/api/acme/renewal-timing/"+mode, strings.NewReader(body))
	r.Header.Set("Origin", "http://"+localHost)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("X-Rootwell-Request", "1")
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := &timingRecorder{ResponseRecorder: httptest.NewRecorder()}
	g.ServeHTTP(w, r)
	return w
}
func timingBody(fp string, gen uint64, mode string) string {
	v := map[string]any{"provider": "letsencrypt-staging", "fingerprint": fp, "expected_generation": gen}
	if mode != "status" {
		v["password"] = nextTestPassword
		v["confirm"] = true
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func TestRenewalTimingRequestStrictShapesAndNoPartialSecret(t *testing.T) {
	fp := strings.Repeat("AA:", 31) + "AA"
	for _, mode := range []string{"status", "check", "interrupt"} {
		good := timingBody(fp, 13, mode)
		cases := []struct {
			body string
			want bool
		}{{good, true}, {"null", false}, {"[]", false}, {"{}", false}, {good + "{}", false}, {string([]byte{255}), false}, {strings.Repeat(" ", 2049), false},
			{strings.TrimSuffix(good, "}") + `,"fingerprint":"` + fp + `"}`, false}, {strings.TrimSuffix(good, "}") + `,"url":"http://127.0.0.1"}`, false},
			{strings.Replace(good, `"expected_generation":13`, `"expected_generation":0`, 1), false}, {strings.Replace(good, `"expected_generation":13`, `"expected_generation":null`, 1), false},
			{strings.Replace(good, `"fingerprint"`, `"Fingerprint"`, 1), false}, {strings.Replace(good, `"letsencrypt-staging"`, `"production"`, 1), false}}
		if mode == "status" {
			cases = append(cases, struct {
				body string
				want bool
			}{strings.TrimSuffix(good, "}") + `,"password":"secret-sentinel"}`, false})
		} else {
			for _, old := range []string{`"confirm":true`, `"password":"` + nextTestPassword + `"`} {
				cases = append(cases, struct {
					body string
					want bool
				}{strings.Replace(good, old, strings.Split(old, ":")[0]+":null", 1), false})
			}
		}
		for _, tc := range cases {
			r := httptest.NewRequest("POST", "/", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			input, ok := readTimingInput(httptest.NewRecorder(), r, mode)
			if ok != tc.want || !ok && input != (timingInput{}) {
				t.Fatal("unsafe input or partial credential accepted", mode)
			}
		}
	}
}

func TestRenewalTimingGateOriginSetupNativeAndBoundedResponse(t *testing.T) {
	g, cookie, _ := readyDirectoryGate(t)
	body := timingBody(strings.Repeat("AA:", 31)+"AA", 13, "status")
	if w := timingCall(g, "status", body, nil); w.Code != 401 {
		t.Fatal("anonymous timing exposed")
	}
	if w := accountCall(g, "POST", "/api/acme/renewal-timing/status", body, cookie, "https://evil.invalid", true); w.Code != 403 {
		t.Fatal("foreign origin allowed")
	}
	if w := accountCall(g, "POST", "/api/acme/renewal-timing/status", body, cookie, "http://"+localHost, false); w.Code != 403 {
		t.Fatal("missing request header allowed")
	}
	if w := accountCall(g, "POST", "/api/acme/renewal-timing/status", body, cookie, "http://"+localHost, true); w.Code != 503 {
		t.Fatal("unbounded writer allowed")
	}
	w := timingCall(g, "status", body, cookie)
	if w.readDeadline.IsZero() || w.writeDeadline.IsZero() || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("request not bounded/private")
	}
	if runtime.GOOS != "linux" && w.Code != 503 {
		t.Fatal("native gained timing custody")
	}
	g, _ = testGate(t)
	cookie = sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil))
	if w := timingCall(g, "status", body, cookie); w.Code != 403 {
		t.Fatal("setup session allowed")
	}
	for _, asset := range []string{"/renewal-timing.js", "/automation"} {
		if w := call(g, "GET", asset, "", nil); w.Code != 303 {
			t.Fatal("anonymous timing asset exposed")
		}
	}
}

func FuzzRenewalTimingRequest(f *testing.F) {
	f.Add(timingBody(strings.Repeat("AA:", 31)+"AA", 13, "status"), "status")
	f.Add(timingBody(strings.Repeat("AA:", 31)+"AA", 13, "check"), "check")
	f.Add("{}", "other")
	f.Fuzz(func(t *testing.T, body, mode string) {
		if len(body) > 4096 || len(mode) > 32 {
			t.Skip()
		}
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		input, ok := readTimingInput(httptest.NewRecorder(), r, mode)
		if !ok && input != (timingInput{}) {
			t.Fatal("refusal exposed partial credential")
		}
		if ok && (input.Expected < 1 || input.Expected > 1000000 || mode == "status" && input.Password != "") {
			t.Fatal("request escaped scope")
		}
	})
}
