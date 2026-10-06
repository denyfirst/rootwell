//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

func TestLinuxInventoryWorkbenchRequiresAuthorityAndExactSnapshot(t *testing.T) {
	g, path := testGate(t)
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	code, err := instanceaccess.EnrollRecovery(path, nextTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	backup := t.TempDir()
	if err := os.Chmod(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := instanceaccess.InitializeInventory(path, filepath.Join(backup, "initial.rwfull"), nextTestPassword, code); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	page := call(g, "GET", "/inventory", "", cookie)
	if page.Header().Get("Referrer-Policy") != "same-origin" || !strings.Contains(page.Header().Get("Content-Security-Policy"), "form-action 'self'") ||
		!strings.Contains(page.Body.String(), `<meta name="referrer" content="same-origin">`) {
		t.Fatal("native POST origin would be suppressed")
	}
	cert, err := os.ReadFile("../../web/workbench/rootwell-demo-bundle.pem")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"certificate": cert, "owner": "not-in-handoff", "location": "private-location-note"})
	w := inventoryCall(g, "POST", "/api/inventory", string(body), cookie, "http://"+localHost, true)
	var saved inventoryOutput
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &saved) != nil || len(saved.Records) < 2 {
		t.Fatal("fixture import failed")
	}
	if err := os.WriteFile(filepath.Join(g.assets.Name(), "index.html"), []byte("<body>"+inventoryWorkbenchMarker+"</body>"), 0o600); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(filepath.Dir(path), "inventory.json")
	before, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"fingerprint": {saved.Records[1].Fingerprint}, "expected_generation": {"2"}, "tool": {"verify"}}
	request := func() *http.Request {
		r := httptest.NewRequest("POST", "http://"+localHost+"/workbench", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://"+localHost)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
		r.AddCookie(cookie)
		return r
	}
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
		want   int
	}{
		{"success", func(*http.Request) {}, http.StatusOK},
		{"anonymous", func(r *http.Request) { r.Header.Del("Cookie") }, http.StatusUnauthorized},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "http://evil.invalid") }, http.StatusForbidden},
		{"missing origin", func(r *http.Request) { r.Header.Del("Origin") }, http.StatusForbidden},
		{"null origin", func(r *http.Request) { r.Header.Set("Origin", "null") }, http.StatusForbidden},
		{"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		{"missing metadata", func(r *http.Request) { r.Header.Del("Sec-Fetch-Mode") }, http.StatusForbidden},
		{"fetch not navigation", func(r *http.Request) { r.Header.Set("Sec-Fetch-Mode", "cors") }, http.StatusForbidden},
		{"iframe", func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", "iframe") }, http.StatusForbidden},
		{"query", func(r *http.Request) { r.URL.RawQuery = "tool=verify" }, http.StatusBadRequest},
		{"host", func(r *http.Request) { r.Host = "evil.invalid" }, http.StatusBadRequest},
		{"GET", func(r *http.Request) { r.Method = "GET" }, http.StatusMethodNotAllowed},
		{"HEAD", func(r *http.Request) { r.Method = "HEAD" }, http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request()
			tc.change(r)
			out := httptest.NewRecorder()
			g.ServeHTTP(out, r)
			if out.Code != tc.want || out.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response %d, want %d", out.Code, tc.want)
			}
			if tc.want == http.StatusOK {
				if !strings.Contains(out.Body.String(), saved.Records[1].Fingerprint) || strings.Contains(out.Body.String(), saved.Records[0].Fingerprint) ||
					strings.Contains(out.Body.String(), "not-in-handoff") || strings.Contains(out.Body.String(), "private-location") {
					t.Fatal("wrong record or notes transferred")
				}
			} else if strings.Contains(out.Body.String(), "rootwell.inventory.workbench.v1") {
				t.Fatal("refusal released certificate")
			}
		})
	}
	for _, selection := range []url.Values{
		{"fingerprint": {saved.Records[1].Fingerprint}, "expected_generation": {"1"}, "tool": {"inspect"}},
		{"fingerprint": {strings.Repeat("00:", 31) + "00"}, "expected_generation": {"2"}, "tool": {"inspect"}},
	} {
		form = selection
		out := httptest.NewRecorder()
		g.ServeHTTP(out, request())
		if out.Code != http.StatusConflict || strings.Contains(out.Body.String(), "inventory-source") {
			t.Fatal("stale or missing record accepted")
		}
	}
	after, err := os.ReadFile(image)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("handoff wrote inventory")
	}
	form = url.Values{"fingerprint": {saved.Records[1].Fingerprint}, "expected_generation": {"2"}, "tool": {"inspect"}}
	if err := os.WriteFile(image, []byte("corrupt authenticated image"), 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := httptest.NewRecorder()
	g.ServeHTTP(corrupt, request())
	if corrupt.Code < 400 || strings.Contains(corrupt.Body.String(), saved.Records[1].Fingerprint) {
		t.Fatal("corrupt image released public object")
	}
	if err := os.WriteFile(image, before, 0o600); err != nil {
		t.Fatal(err)
	}
	g.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
	out := httptest.NewRecorder()
	g.ServeHTTP(out, request())
	if out.Code != http.StatusUnauthorized {
		t.Fatal("expired session released certificate")
	}
	g.now = time.Now
	cookie = sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	if err := os.WriteFile(path, []byte("changed access envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	revoked := httptest.NewRecorder()
	g.ServeHTTP(revoked, request())
	if revoked.Code != http.StatusUnauthorized {
		t.Fatal("changed access envelope released public object")
	}
}
