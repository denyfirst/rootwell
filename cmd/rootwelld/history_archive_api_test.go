package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func archiveBody(generation uint64) string {
	b, _ := json.Marshal(map[string]any{"expected_generation": generation, "password": nextTestPassword, "confirm": true, "backup_confirmed": true, "scope": "lossless-history-archive"})
	return string(b)
}
func archiveCall(g *gate, mode, body string, cookie *http.Cookie) *timingRecorder {
	r := httptest.NewRequest("POST", "http://"+localHost+"/api/inventory/history/"+mode, strings.NewReader(body))
	r.Header.Set("Origin", "http://"+localHost)
	r.Header.Set("X-Rootwell-Request", "1")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := &timingRecorder{ResponseRecorder: httptest.NewRecorder()}
	g.ServeHTTP(w, r)
	return w
}
func TestHistoryArchiveStrictInputAndNoPartialSecret(t *testing.T) {
	parse := func(body string, write bool) bool {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		out, ok := readHistoryArchiveInput(httptest.NewRecorder(), r, write)
		if !ok && out != (historyArchiveInput{}) {
			t.Fatal("partial credential on refusal")
		}
		return ok
	}
	good := archiveBody(513)
	if !parse(good, true) || !parse("{}", false) {
		t.Fatal("valid request refused")
	}
	for _, bad := range []string{good, `null`, `[]`, `{"password":"secret"}`, `{"scope":"lossless-history-archive","scope":"lossless-history-archive"}`, strings.Repeat("x", 2049), "{\xff}", `{} {}`} {
		if parse(bad, false) {
			t.Fatal("status accepted fields/malformed")
		}
	}
	for _, bad := range []string{`{}`, good + " " + good, strings.Replace(good, `"confirm":true`, `"confirm":false`, 1), strings.Replace(good, `"backup_confirmed":true`, `"backup_confirmed":null`, 1), strings.Replace(good, `"expected_generation":513`, `"expected_generation":0`, 1), strings.Replace(good, `"password":`, `"password":null,"extra":`, 1), strings.Replace(good, `lossless-history-archive`, `session-timing-only`, 1), strings.Replace(good, `"scope":`, `"scope":"lossless-history-archive","scope":`, 1)} {
		if parse(bad, true) {
			t.Fatal("invalid consent or malformed input admitted")
		}
	}
}

func TestHistoryArchiveAccessBoundaryBeforeStorage(t *testing.T) {
	g, cookie, _ := readyDirectoryGate(t)
	if w := archiveCall(g, "status", "{}", nil); w.Code != 401 {
		t.Fatal("anonymous metadata exposed")
	}
	if w := accountCall(g, "POST", "/api/inventory/history/status", "{}", cookie, "https://foreign.invalid", true); w.Code != 403 {
		t.Fatal("foreign origin admitted")
	}
	if runtime.GOOS != "linux" {
		if w := archiveCall(g, "archive", archiveBody(513), cookie); w.Code != 503 {
			t.Fatal("native archive admitted", w.Code)
		}
	}
}
func FuzzHistoryArchiveInput(f *testing.F) {
	f.Add([]byte(archiveBody(513)), true)
	f.Add([]byte("{}"), false)
	f.Fuzz(func(t *testing.T, body []byte, write bool) {
		if len(body) > 4096 {
			t.Skip()
		}
		r := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		s, ok := readHistoryArchiveInput(httptest.NewRecorder(), r, write)
		if !ok && s != (historyArchiveInput{}) {
			t.Fatal("partial parsed credential")
		}
	})
}
