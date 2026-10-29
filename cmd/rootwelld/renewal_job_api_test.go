package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func renewalJobBody(fp string, gen uint64, mode string) string {
	value := map[string]any{"provider": "letsencrypt-staging"}
	if mode == "preview" || mode == "start" {
		value["fingerprint"] = fp
		value["expected_generation"] = gen
	}
	if mode == "start" {
		value["password"] = nextTestPassword
		value["confirm"] = true
		value["exclusive_dns"] = true
		value["scope"] = renewalJobScope
	}
	if mode == "stop" {
		value["job_id"] = strings.Repeat("ab", 16)
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}

func renewalCall(g *gate, mode, body string, cookie *http.Cookie) *timingRecorder {
	r := httptest.NewRequest("POST", "http://"+localHost+"/api/acme/renewal-job/"+mode, strings.NewReader(body))
	r.Header.Set("Origin", "http://"+localHost)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Rootwell-Request", "1")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := &timingRecorder{ResponseRecorder: httptest.NewRecorder()}
	g.ServeHTTP(w, r)
	return w
}

func TestRenewalJobStrictIndependentConsentAndZeroPartialSecrets(t *testing.T) {
	fp := strings.Repeat("AB:", 31) + "AB"
	for _, mode := range []string{"preview", "start", "status", "stop"} {
		good := renewalJobBody(fp, 13, mode)
		parse := func(body string) bool {
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			out, ok := readRenewalJobInput(httptest.NewRecorder(), r, mode)
			if !ok && out != (watchInput{}) {
				t.Fatal("partial grant escaped")
			}
			return ok
		}
		if !parse(good) {
			t.Fatal("valid grant refused", mode)
		}
		bad := []string{"null", "[]", "{}", good + "{}", string([]byte{255}), strings.Repeat(" ", 2049), strings.TrimSuffix(good, "}") + `,"provider":"letsencrypt-staging"}`, strings.TrimSuffix(good, "}") + `,"url":"http://127.0.0.1"}`, strings.TrimSuffix(good, "}") + `,"resume":true` + "}"}
		if mode == "start" {
			bad = append(bad, watchBody(fp, 13, "start"), strings.Replace(good, `"confirm":true`, `"confirm":false`, 1), strings.Replace(good, `"exclusive_dns":true`, `"exclusive_dns":false`, 1), strings.Replace(good, renewalJobScope, watchScope, 1), strings.Replace(good, `"password":"`+nextTestPassword+`"`, `"password":null`, 1))
		}
		if mode == "preview" {
			bad = append(bad, strings.Replace(good, `:13`, `:null`, 1), strings.Replace(good, `:13`, `:1e3`, 1))
		}
		if mode == "stop" {
			bad = append(bad, strings.Replace(good, strings.Repeat("ab", 16), strings.Repeat("AB", 16), 1))
		}
		for _, body := range bad {
			if parse(body) {
				t.Fatal("unscoped/malformed grant admitted", mode, body)
			}
		}
	}
}

func TestRenewalJobStatusOwnerStopOriginAndNativeRefusal(t *testing.T) {
	g, cookie, _ := readyDirectoryGate(t)
	if w := call(g, "GET", "/renewal-job.js", "", nil); w.Code != http.StatusSeeOther {
		t.Fatal("anonymous job script", w.Code)
	}
	if w := call(g, "GET", "/renewal-job.js", "", cookie); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "session-test-renewal") {
		t.Fatal("protected job UI unavailable", w.Code)
	}
	body := renewalJobBody("", 0, "status")
	if w := renewalCall(g, "status", body, nil); w.Code != 401 {
		t.Fatal("anonymous status", w.Code)
	}
	if w := accountCall(g, "POST", "/api/acme/renewal-job/status", body, cookie, "https://evil.invalid", true); w.Code != 403 {
		t.Fatal("foreign origin", w.Code)
	}
	w := renewalCall(g, "status", body, cookie)
	var out renewalJobOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Job.State != "not-running" || out.Readiness != nil || !out.TestOnly || g.renewal != nil || w.readDeadline.IsZero() {
		t.Fatal("status created authority", w.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	close(done)
	j := &renewalJob{owner: watchOwner(cookie.Value), id: strings.Repeat("ab", 16), state: "waiting", reason: "ready", ctx: ctx, cancel: cancel, done: done, last: g.now(), expires: g.now().Add(time.Hour)}
	g.mu.Lock()
	g.renewal = j
	g.mu.Unlock()
	if got := g.renewalSnapshot(watchOwner("unrelated")); got.ID != "" || got.State != "not-running" {
		t.Fatal("another session received job")
	}
	g.derive <- struct{}{}
	w = renewalCall(g, "stop", renewalJobBody("", 0, "stop"), cookie)
	<-g.derive
	if w.Code != 200 || j.state != "paused" || j.reason != "stopped" || j.ctx.Err() == nil || !j.next.IsZero() {
		t.Fatal("stop needed crypto or retained authority", w.Code)
	}
	if runtime.GOOS != "linux" {
		if w := renewalCall(g, "start", renewalJobBody(strings.Repeat("AB:", 31)+"AB", 13, "start"), cookie); w.Code != 503 {
			t.Fatal("native granted renewal", w.Code)
		}
	}
}

func TestRenewalJobConstructorSessionBoundsAndMutualExclusion(t *testing.T) {
	owner := watchOwner("original")
	now := time.Now()
	base := session{inventoryReady: true, expires: now.Add(time.Hour), revision: [32]byte{1}}
	for _, mode := range []string{"missing", "setup", "unready", "revision", "expiry", "expired", "extended", "closed", "watch-finishing", "renewal-finishing"} {
		g := &gate{now: func() time.Time { return now }, sessions: map[[32]byte]session{owner: base}}
		s := base
		switch mode {
		case "missing":
			delete(g.sessions, owner)
		case "setup":
			v := base
			v.setup = true
			g.sessions[owner] = v
		case "unready":
			v := base
			v.inventoryReady = false
			g.sessions[owner] = v
		case "revision":
			s.revision[0] ^= 1
		case "expiry":
			s.expires = s.expires.Add(time.Second)
		case "expired":
			s.expires = now
			g.sessions[owner] = s
		case "extended":
			s.expires = now.Add(13 * time.Hour)
			g.sessions[owner] = s
		case "closed":
			g.closed = true
		case "watch-finishing":
			g.watch = &timingWatch{done: make(chan struct{})}
		case "renewal-finishing":
			g.renewal = &renewalJob{done: make(chan struct{})}
		}
		prior := g.renewal
		if out, err := g.newRenewalJob(owner, s, inventorystore.RenewalCycle{}); err == nil || out != nil || g.renewal != prior {
			t.Fatal("invalid original session granted", mode)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	j := &renewalJob{state: "waiting", next: now.Add(time.Hour), ctx: ctx, cancel: cancel, owner: owner}
	g := &gate{renewal: j, now: func() time.Time { return now }, sessions: map[[32]byte]session{owner: base}}
	g.deferRenewal(j)
	if j.next != now.Add(time.Hour) {
		t.Fatal("busy shortened wait")
	}
	g.forgetSessionLocked(owner)
	if activeRenewal(j) || j.ctx.Err() == nil {
		t.Fatal("logout retained authority")
	}
	j.state, j.reason = "complete", "complete"
	g.pauseRenewalLocked(j, "server-stopped")
	if j.state != "complete" || j.reason != "complete" {
		t.Fatal("shutdown lost confirmed completion")
	}
	typ := reflect.TypeFor[renewalJob]()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		for _, secret := range []string{"password", "dataKey", "signer", "credential", "installationID", "session"} {
			if strings.Contains(strings.ToLower(f.Name), strings.ToLower(secret)) {
				t.Fatal("job retained unlock", f.Name)
			}
		}
	}
}

func FuzzRenewalJobInput(f *testing.F) {
	f.Add([]byte(renewalJobBody(strings.Repeat("AB:", 31)+"AB", 13, "start")))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			t.Skip()
		}
		for _, mode := range []string{"preview", "start", "status", "stop"} {
			r := httptest.NewRequest("POST", "/", bytes.NewReader(b))
			r.Header.Set("Content-Type", "application/json")
			out, ok := readRenewalJobInput(httptest.NewRecorder(), r, mode)
			if !ok && out != (watchInput{}) {
				t.Fatal("partial grant")
			}
		}
	})
}
