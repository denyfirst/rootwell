package main

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func requestArchiveBody(generation uint64) string {
	return strings.Replace(archiveBody(generation), "lossless-history-archive", "lossless-request-archive", 1)
}

func requestArchiveCall(g *gate, mode, body string, cookie *http.Cookie) *timingRecorder {
	r := httptest.NewRequest("POST", "http://"+localHost+"/api/acme/request-storage/"+mode, strings.NewReader(body))
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

func TestRequestArchiveStrictScopeAndAccessBoundary(t *testing.T) {
	good := requestArchiveBody(37)
	parse := func(body string, write bool) bool {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		s, ok := readStorageArchiveInput(httptest.NewRecorder(), r, write, "lossless-request-archive")
		if !ok && s != (historyArchiveInput{}) {
			t.Fatal("partial request-archive credential")
		}
		return ok
	}
	if !parse(good, true) || !parse("{}", false) {
		t.Fatal("valid request archive input refused")
	}
	for _, bad := range []string{archiveBody(37), good + good, strings.Replace(good, `"confirm":true`, `"confirm":false`, 1), strings.Replace(good, `"backup_confirmed":true`, `"backup_confirmed":null`, 1), strings.Replace(good, `"scope":`, `"scope":"lossless-request-archive","scope":`, 1), `{"password":"secret-sentinel"}`, strings.Repeat("x", 2049), "{\xff}"} {
		if parse(bad, true) {
			t.Fatal("wrong scope or malformed request archive admitted")
		}
	}
	if parse(good, false) {
		t.Fatal("status accepted write authority")
	}
	g, cookie, _ := readyDirectoryGate(t)
	if w := call(g, "GET", "/request-archive.js", "", cookie); w.Code != 200 || !strings.Contains(w.Body.String(), "lossless-request-archive") {
		t.Fatal("ready request storage UI unavailable")
	}
	if w := requestArchiveCall(g, "status", "{}", nil); w.Code != 401 {
		t.Fatal("anonymous request history exposed")
	}
	if w := accountCall(g, "POST", "/api/acme/request-storage/status", "{}", cookie, "https://foreign.invalid", true); w.Code != 403 {
		t.Fatal("foreign request history origin admitted")
	}
	if w := requestArchiveCall(g, "archive", archiveBody(37), cookie); w.Code != 400 {
		t.Fatal("history consent reused for request archive", w.Code)
	}
	if runtime.GOOS != "linux" {
		if w := requestArchiveCall(g, "archive", good, cookie); w.Code != 503 {
			t.Fatal("native request archive admitted", w.Code)
		}
	}
}
