//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

func inventoryCall(g *gate, method, route, body string, cookie *http.Cookie, origin string, header bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+localHost+route, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if header {
		r.Header.Set("X-Rootwell-Request", "1")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func TestLinuxInventoryAPIRequiresReadySessionAndExplicitSave(t *testing.T) {
	g, path := testGate(t)
	if w := inventoryCall(g, "GET", "/inventory", "", nil, "", true); w.Code != http.StatusSeeOther {
		t.Fatal("anonymous inventory page opened")
	}
	if w := inventoryCall(g, "GET", "/inventory.js", "", nil, "", false); w.Code != http.StatusSeeOther {
		t.Fatal("anonymous inventory script opened")
	}
	if w := inventoryCall(g, "GET", "/api/inventory", "", nil, "", true); w.Code != http.StatusUnauthorized {
		t.Fatal("anonymous inventory API opened")
	}
	setup := call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil)
	setupCookie := sessionCookie(t, setup)
	if w := inventoryCall(g, "GET", "/api/inventory", "", setupCookie, "", true); w.Code != http.StatusForbidden {
		t.Fatal("setup session opened inventory")
	}
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	ready := call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil)
	if ready.Code != http.StatusOK {
		t.Fatalf("ready sign-in: %d", ready.Code)
	}
	readyCookie := sessionCookie(t, ready)
	if w := inventoryCall(g, "GET", "/api/inventory", "", readyCookie, "", true); w.Code != http.StatusConflict {
		t.Fatal("uninitialized inventory opened")
	}
	code, err := instanceaccess.EnrollRecovery(path, nextTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	backupDir := t.TempDir()
	if err := os.Chmod(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := instanceaccess.InitializeInventory(path, filepath.Join(backupDir, "initial.rwfull"), nextTestPassword, code); err != nil {
		t.Fatal(err)
	}
	if w := inventoryCall(g, "GET", "/api/inventory", "", readyCookie, "", true); w.Code != http.StatusUnauthorized {
		t.Fatal("session survived recovery enrollment")
	}
	ready = call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil)
	readyCookie = sessionCookie(t, ready)
	if w := inventoryCall(g, "GET", "/api/inventory", "", readyCookie, "", false); w.Code != http.StatusForbidden {
		t.Fatal("GET without explicit request header accepted")
	}
	crossSite := httptest.NewRequest("GET", "http://"+localHost+"/api/inventory", nil)
	crossSite.AddCookie(readyCookie)
	crossSite.Header.Set("X-Rootwell-Request", "1")
	crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	crossResult := httptest.NewRecorder()
	g.ServeHTTP(crossResult, crossSite)
	if crossResult.Code != http.StatusForbidden {
		t.Fatal("cross-site inventory read accepted")
	}
	if w := inventoryCall(g, "GET", "/api/inventory", "", readyCookie, "", true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"generation":1`) {
		t.Fatalf("empty inventory: %d %s", w.Code, w.Body.String())
	}
	cert, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"certificate": cert, "owner": "Platform", "location": "production/nginx"})
	if err != nil {
		t.Fatal(err)
	}
	if w := inventoryCall(g, "POST", "/api/inventory", string(payload), readyCookie, "http://evil.invalid", true); w.Code != http.StatusForbidden {
		t.Fatal("cross-origin save accepted")
	}
	if w := inventoryCall(g, "POST", "/api/inventory", string(payload), readyCookie, "http://"+localHost, false); w.Code != http.StatusForbidden {
		t.Fatal("save without CSRF header accepted")
	}
	if w := inventoryCall(g, "POST", "/api/inventory", `{"certificate":"AA==","certificate":"AA=="}`, readyCookie, "http://"+localHost, true); w.Code != http.StatusBadRequest {
		t.Fatal("duplicate JSON field accepted")
	}
	secretPayload, _ := json.Marshal(map[string]any{"certificate": []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")})
	if w := inventoryCall(g, "POST", "/api/inventory", string(secretPayload), readyCookie, "http://"+localHost, true); w.Code != http.StatusBadRequest {
		t.Fatal("private-key input saved")
	}
	saved := inventoryCall(g, "POST", "/api/inventory", string(payload), readyCookie, "http://"+localHost, true)
	if saved.Code != http.StatusCreated || !strings.Contains(saved.Body.String(), `"import_generation":2`) || !strings.Contains(saved.Body.String(), `"imported_at":`) || bytes.Contains(saved.Body.Bytes(), cert) {
		t.Fatalf("public save: %d %s", saved.Code, saved.Body.String())
	}
	if w := inventoryCall(g, "POST", "/api/inventory", string(payload), readyCookie, "http://"+localHost, true); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "already saved") {
		t.Fatal("duplicate was not explained")
	}
	listed := inventoryCall(g, "GET", "/api/inventory", "", readyCookie, "", true)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"verification":"not-performed"`) || !strings.Contains(listed.Body.String(), `"generation":2`) || !strings.Contains(listed.Body.String(), "Platform") {
		t.Fatalf("saved record unreadable: %d %s", listed.Code, listed.Body.String())
	}
	if strings.Contains(listed.Body.String(), "PRIVATE KEY") || bytes.Contains(listed.Body.Bytes(), cert) {
		t.Fatal("API leaked source bytes or key")
	}
	if w := inventoryCall(g, "GET", "/inventory", "", readyCookie, "", false); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Different from offline Workbench") {
		t.Fatal("inventory page unavailable")
	}
	for _, asset := range []string{"/inventory.js", "/inventory.css"} {
		if w := inventoryCall(g, "GET", asset, "", readyCookie, "", false); w.Code != http.StatusOK {
			t.Fatalf("protected asset %s unavailable: %d", asset, w.Code)
		}
	}
	inventoryPath := filepath.Join(filepath.Dir(path), "inventory.json")
	encrypted, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	encrypted[len(encrypted)/2] ^= 1
	if err := os.WriteFile(inventoryPath, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	if w := inventoryCall(g, "GET", "/api/inventory", "", readyCookie, "", true); w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "Platform") {
		t.Fatal("corrupt inventory returned records")
	}
}
