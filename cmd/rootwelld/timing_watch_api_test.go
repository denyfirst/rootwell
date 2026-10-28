package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func watchBody(fp string, gen uint64, mode string) string {
	d := map[string]any{"provider": "letsencrypt-staging"}
	if mode == "preview" || mode == "start" {
		d["fingerprint"] = fp
		d["expected_generation"] = gen
	}
	if mode == "start" {
		d["password"] = nextTestPassword
		d["confirm"] = true
		d["scope"] = watchScope
	}
	if mode == "stop" {
		d["watch_id"] = strings.Repeat("ab", 16)
	}
	b, _ := json.Marshal(d)
	return string(b)
}
func watchCall(g *gate, mode, body string, cookie *http.Cookie) *timingRecorder {
	r := httptest.NewRequest("POST", "http://"+localHost+"/api/acme/timing-watch/"+mode, strings.NewReader(body))
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
func TestTimingWatchStrictSeparateConsentAndNoPartialSecret(t *testing.T) {
	fp := strings.Repeat("AA:", 31) + "AA"
	for _, mode := range []string{"preview", "start", "status", "stop"} {
		good := watchBody(fp, 13, mode)
		parse := func(body string) bool {
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			value, ok := readWatchInput(httptest.NewRecorder(), r, mode)
			if !ok && value != (watchInput{}) {
				t.Fatal("partial secret returned")
			}
			return ok
		}
		if !parse(good) {
			t.Fatal("legitimate watch input refused", mode)
		}
		bad := []string{"null", "[]", "{}", good + "{}", string([]byte{255}), strings.Repeat(" ", 2049), strings.TrimSuffix(good, "}") + `,"provider":"letsencrypt-staging"}`, strings.TrimSuffix(good, "}") + `,"url":"http://127.0.0.1"}`, strings.TrimSuffix(good, "}") + `,"interval":1}`}
		if mode == "start" {
			bad = append(bad, timingBody(fp, 13, "check"), strings.Replace(good, `"confirm":true`, `"confirm":false`, 1), strings.Replace(good, watchScope, "session-renewal", 1), strings.Replace(good, `"password":"`+nextTestPassword+`"`, `"password":null`, 1))
		}
		if mode == "preview" {
			bad = append(bad, strings.Replace(good, `:13`, `:null`, 1))
		}
		if mode == "stop" {
			bad = append(bad, strings.Replace(good, strings.Repeat("ab", 16), strings.Repeat("AB", 16), 1))
		}
		for _, body := range bad {
			if parse(body) {
				t.Fatal("unscoped/malformed watch admitted", mode)
			}
		}
	}
}
func TestTimingWatchGateStatusDoesNotGrantOrPersistAuthority(t *testing.T) {
	g, cookie, _ := readyDirectoryGate(t)
	status := watchBody("", 0, "status")
	if w := watchCall(g, "status", status, nil); w.Code != 401 {
		t.Fatal("anonymous watch status exposed")
	}
	if w := accountCall(g, "POST", "/api/acme/timing-watch/status", status, cookie, "https://evil.invalid", true); w.Code != 403 {
		t.Fatal("foreign origin admitted")
	}
	w := watchCall(g, "status", status, cookie)
	var out watchOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Watch.State != "not-running" || out.AutomaticRenewal || out.Readiness != nil || g.watch != nil || w.readDeadline.IsZero() {
		t.Fatal("status acquired authority", w.Code)
	}
	if runtime.GOOS != "linux" {
		if w := watchCall(g, "start", watchBody(strings.Repeat("AA:", 31)+"AA", 13, "start"), cookie); w.Code != 503 || g.watch != nil {
			t.Fatal("native started watch")
		}
	}
}
func FuzzTimingWatchInput(f *testing.F) {
	f.Add([]byte(watchBody(strings.Repeat("AA:", 31)+"AA", 13, "start")))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			t.Skip()
		}
		for _, mode := range []string{"preview", "start", "status", "stop"} {
			r := httptest.NewRequest("POST", "/", bytes.NewReader(b))
			r.Header.Set("Content-Type", "application/json")
			out, ok := readWatchInput(httptest.NewRecorder(), r, mode)
			if !ok && out != (watchInput{}) {
				t.Fatal("partial watch input")
			}
		}
	})
}
