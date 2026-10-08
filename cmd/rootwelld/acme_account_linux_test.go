//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

func accountGateFixture(t *testing.T) (*gate, *http.Cookie, string) {
	t.Helper()
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
	return g, cookie, filepath.Join(filepath.Dir(path), "inventory.json")
}

func TestLinuxAccountAPIReauthStaleAndNoReplacement(t *testing.T) {
	g, cookie, path := accountGateFixture(t)
	prior := http.DefaultTransport
	http.DefaultTransport = refuseACMETransport{}
	t.Cleanup(func() { http.DefaultTransport = prior })
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := accountCall(g, "POST", "/api/acme/account/status", accountStatusInput, cookie, "http://"+localHost, true)
	var result accountOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.State != "not-prepared" || result.Generation != 1 {
		t.Fatal("status not available")
	}
	for _, tc := range []struct {
		body string
		want int
	}{
		{strings.Replace(accountPrepareInput, nextTestPassword, "wrong-secret-sentinel", 1), 401},
		{strings.Replace(accountPrepareInput, `"expected_generation":1`, `"expected_generation":2`, 1), 409},
	} {
		w := accountCall(g, "POST", "/api/acme/account/prepare", tc.body, cookie, "http://"+localHost, true)
		if w.Code != tc.want || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("reauth/stale refused incorrectly")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(after, before) {
			t.Fatal("refusal changed store")
		}
	}
	g.derive <- struct{}{}
	if w := accountCall(g, "POST", "/api/acme/account/prepare", accountPrepareInput, cookie, "http://"+localHost, true); w.Code != 503 {
		t.Fatal("busy derivation accepted")
	}
	<-g.derive
	w = accountCall(g, "POST", "/api/acme/account/prepare", accountPrepareInput, cookie, "http://"+localHost, true)
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &result) != nil || !result.Saved || result.State != "key-prepared" || result.Generation != 2 || result.CanIssue || result.AccountCreated || result.TermsAccepted || result.NetworkUsed || strings.Contains(w.Body.String(), nextTestPassword) || strings.Contains(w.Body.String(), "private_key") {
		t.Fatal("preparation failed or leaked/granted authority")
	}
	saved, _ := os.ReadFile(path)
	if w := accountCall(g, "POST", "/api/acme/account/prepare", strings.Replace(accountPrepareInput, `"expected_generation":1`, `"expected_generation":2`, 1), cookie, "http://"+localHost, true); w.Code != 409 {
		t.Fatal("existing account replaced")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(saved, after) {
		t.Fatal("duplicate changed account")
	}
	w = accountCall(g, "POST", "/api/acme/account/status", accountStatusInput, cookie, "http://"+localHost, true)
	var again accountOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &again) != nil || again != result {
		t.Fatal("status lost saved identity")
	}
	// Shared budget also applies to account preparation, not just login/export.
	if w := accountCall(g, "POST", "/api/acme/account/prepare", accountPrepareInput, cookie, "http://"+localHost, true); w.Code != 429 {
		t.Fatal("shared attempt budget bypassed")
	}
}

func TestLinuxAccountRequestLogoutAndCancellationCannotWrite(t *testing.T) {
	for _, boundary := range []string{"logout", "cancel", "missing-fetch-metadata"} {
		t.Run(boundary, func(t *testing.T) {
			g, cookie, path := accountGateFixture(t)
			before, _ := os.ReadFile(path)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := &acmeReadHook{Reader: strings.NewReader(accountPrepareInput), onRead: func() {
				if boundary == "cancel" {
					cancel()
				}
				if boundary == "logout" {
					call(g, "DELETE", "/api/session", "", cookie)
				}
			}}
			r := httptest.NewRequest("POST", "http://"+localHost+"/api/acme/account/prepare", body).WithContext(ctx)
			r.AddCookie(cookie)
			r.Header.Set("Origin", "http://"+localHost)
			r.Header.Set("X-Rootwell-Request", "1")
			r.Header.Set("Content-Type", "application/json")
			if boundary != "missing-fetch-metadata" {
				r.Header.Set("Sec-Fetch-Site", "same-origin")
			}
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code < 400 || strings.Contains(w.Body.String(), "key-prepared") {
				t.Fatal("revoked request succeeded")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("revoked request wrote image")
			}
		})
	}
}
