package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

const directoryConsent = `{"provider":"letsencrypt-staging","confirm":true}`

func TestDirectoryConsentStrictlyRefusesUnconfirmedOrSecretInput(t *testing.T) {
	for _, body := range []string{directoryConsent, `{"confirm":true,"provider":"letsencrypt-staging"}`, "null", "[]", directoryConsent + "{}", strings.Repeat(" ", 4097), string([]byte{0xff}), `{"provider":"letsencrypt-staging"}`, `{"provider":"letsencrypt-staging","confirm":false}`, `{"provider":"letsencrypt-staging","confirm":null}`, `{"Provider":"letsencrypt-staging","confirm":true}`, `{"provider":"production","confirm":true}`, strings.TrimSuffix(directoryConsent, "}") + `,"confirm":true}`, strings.TrimSuffix(directoryConsent, "}") + `,"password":"secret-sentinel"}`, strings.TrimSuffix(directoryConsent, "}") + `,"domains":["example.com"]}`, strings.TrimSuffix(directoryConsent, "}") + `,"directory":"http://127.0.0.1"}`} {
		r := httptest.NewRequest("POST", "/api/acme/directory", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		want := body == directoryConsent || body == `{"confirm":true,"provider":"letsencrypt-staging"}`
		if readDirectoryConsent(httptest.NewRecorder(), r) != want {
			t.Fatal("consent parser accepted unsafe input or refused valid input")
		}
	}
	r := httptest.NewRequest("POST", "/api/acme/directory", strings.NewReader(directoryConsent))
	if readDirectoryConsent(httptest.NewRecorder(), r) {
		t.Fatal("missing JSON media type accepted")
	}
}

func readyDirectoryGate(t *testing.T) (*gate, *http.Cookie, string) {
	t.Helper()
	g, path := testGate(t)
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	return g, cookie, path
}

func TestDirectoryGateRequiresReadyOriginConsentAndThrottlesWithoutStorage(t *testing.T) {
	g, cookie, path := readyDirectoryGate(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	g.directoryCheck = func(ctx context.Context, permit func() bool) (acmestaging.Summary, error) {
		calls++
		if !permit() {
			t.Fatal("live request not authorized")
		}
		return acmestaging.Summary{Schema: "rootwell.acme.directory.v1", NetworkUsed: true}, nil
	}
	for _, bad := range []struct {
		method, route, body, origin string
		cookie                      *http.Cookie
		header                      bool
	}{
		{"POST", "/api/acme/directory", directoryConsent, "http://" + localHost, nil, true},
		{"GET", "/api/acme/directory", directoryConsent, "http://" + localHost, cookie, true},
		{"POST", "/api/acme/directory?x=1", directoryConsent, "http://" + localHost, cookie, true},
		{"POST", "/api/acme/directory", directoryConsent, "http://evil.invalid", cookie, true},
		{"POST", "/api/acme/directory", directoryConsent, "http://" + localHost, cookie, false},
		{"POST", "/api/acme/directory", `{"provider":"letsencrypt-staging","confirm":false}`, "http://" + localHost, cookie, true},
	} {
		w := acmeCall(g, bad.method, bad.route, bad.body, bad.cookie, bad.origin, bad.header)
		if w.Code < 400 || calls != 0 {
			t.Fatal("unauthorized connector invoked")
		}
	}
	if w := call(g, "GET", "/acme-directory.js", "", nil); w.Code != 303 {
		t.Fatal("anonymous connector asset exposed")
	}
	if w := call(g, "GET", "/acme-directory.js", "", cookie); w.Code != 200 {
		t.Fatal("ready connector asset refused")
	}
	w := acmeCall(g, "POST", "/api/acme/directory", directoryConsent, cookie, "http://"+localHost, true)
	if w.Code != 200 || calls != 1 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), `"can_issue":false`) {
		t.Fatal("approved connection failed")
	}
	if w := acmeCall(g, "POST", "/api/acme/directory", directoryConsent, cookie, "http://"+localHost, true); w.Code != 429 || calls != 1 {
		t.Fatal("repeated request not throttled")
	}
	now := g.now()
	g.now = func() time.Time { return now.Add(31 * time.Second) }
	g.directoryBusy = true
	if w := acmeCall(g, "POST", "/api/acme/directory", directoryConsent, cookie, "http://"+localHost, true); w.Code != 429 || calls != 1 {
		t.Fatal("parallel request not refused")
	}
	g.directoryBusy = false
	g.directoryCheck = func(context.Context, func() bool) (acmestaging.Summary, error) {
		return acmestaging.Summary{}, errors.New("secret-sentinel")
	}
	w = acmeCall(g, "POST", "/api/acme/directory", directoryConsent, cookie, "http://"+localHost, true)
	if w.Code != 502 || strings.Contains(w.Body.String(), "secret-sentinel") {
		t.Fatal("connector error reflected")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("directory check modified access image")
	}
	if w := call(g, "DELETE", "/api/session", "", cookie); w.Code != 204 {
		t.Fatal("logout failed")
	}
	if w := acmeCall(g, "POST", "/api/acme/directory", directoryConsent, cookie, "http://"+localHost, true); w.Code != 401 {
		t.Fatal("logged-out check accepted")
	}
}

func TestDirectoryGateRejectsSetupAndLateSessionOrContext(t *testing.T) {
	g, _ := testGate(t)
	g.directoryCheck = func(context.Context, func() bool) (acmestaging.Summary, error) {
		t.Fatal("setup session invoked connector")
		return acmestaging.Summary{}, nil
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil))
	if w := acmeCall(g, "POST", "/api/acme/directory", directoryConsent, cookie, "http://"+localHost, true); w.Code != 403 {
		t.Fatal("setup session accepted")
	}
	for _, boundary := range []string{"body-cancel", "body-expire", "connector-cancel", "connector-expire"} {
		t.Run(boundary, func(t *testing.T) {
			g, cookie, _ := readyDirectoryGate(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			invalidate := func() {
				if strings.HasSuffix(boundary, "expire") {
					now := g.now()
					g.now = func() time.Time { return now.Add(24 * time.Hour) }
				} else {
					cancel()
				}
			}
			body := &acmeReadHook{Reader: strings.NewReader(directoryConsent)}
			if strings.HasPrefix(boundary, "body-") {
				body.onRead = invalidate
			}
			g.directoryCheck = func(ctx context.Context, permit func() bool) (acmestaging.Summary, error) {
				calls++
				invalidate()
				if permit() {
					t.Fatal("connector retained authorization")
				}
				return acmestaging.Summary{NetworkUsed: true, State: "directory-checked"}, nil
			}
			r := httptest.NewRequest("POST", "http://"+localHost+"/api/acme/directory", body).WithContext(ctx)
			r.AddCookie(cookie)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "http://"+localHost)
			r.Header.Set("X-Rootwell-Request", "1")
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code != 401 || strings.Contains(w.Body.String(), "directory-checked") || strings.HasPrefix(boundary, "body-") && calls != 0 {
				t.Fatal("late invalid request returned success or used network")
			}
		})
	}
}

func FuzzDirectoryConsent(f *testing.F) {
	f.Add([]byte(directoryConsent))
	f.Add([]byte(`{"provider":"production","confirm":true}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		r := httptest.NewRequest("POST", "/api/acme/directory", bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		_ = readDirectoryConsent(httptest.NewRecorder(), r)
	})
}

func TestDirectoryInFlightLogoutRefusesResultAndConcurrentCheck(t *testing.T) {
	g, cookie, _ := readyDirectoryGate(t)
	started, release := make(chan struct{}), make(chan struct{})
	g.directoryCheck = func(ctx context.Context, permit func() bool) (acmestaging.Summary, error) {
		close(started)
		<-release
		if permit() {
			t.Error("logout retained network authority")
		}
		return acmestaging.Summary{State: "directory-checked", NetworkUsed: true}, nil
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- acmeCall(g, "POST", "/api/acme/directory", directoryConsent, cookie, "http://"+localHost, true)
	}()
	<-started
	// Separate the in-flight limit from the cooldown, under the same mutex.
	g.mu.Lock()
	g.directoryLast = g.now().Add(-time.Hour)
	g.mu.Unlock()
	w := acmeCall(g, "POST", "/api/acme/directory", directoryConsent, cookie, "http://"+localHost, true)
	if w.Code != 429 {
		close(release)
		<-done
		t.Fatal("concurrent check entered connector")
	}
	if w := call(g, "DELETE", "/api/session", "", cookie); w.Code != 204 {
		close(release)
		<-done
		t.Fatal("logout failed")
	}
	close(release)
	w = <-done
	if w.Code != 401 || strings.Contains(w.Body.String(), "directory-checked") {
		t.Fatal("logged-out operation published success")
	}
	g.mu.Lock()
	busy := g.directoryBusy
	g.mu.Unlock()
	if busy {
		t.Fatal("in-flight slot leaked after refusal")
	}
}
