//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestLinuxCloudflareConfigAPIReauthStaleSharedBudgetAndSecretFreeStatus(t *testing.T) {
	g, cookie, path := accountGateFixture(t)
	prior := http.DefaultTransport
	http.DefaultTransport = refuseACMETransport{}
	t.Cleanup(func() { http.DefaultTransport = prior })
	before, _ := os.ReadFile(path)
	w := accountCall(g, "POST", "/api/dns/cloudflare/status", dnsStatusInput, cookie, "http://"+localHost, true)
	var result dnsConfigOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.State != "not-configured" || result.Generation != 1 || !result.CanChange {
		t.Fatal("initial DNS status unavailable")
	}
	for _, tc := range []struct {
		body string
		want int
	}{
		{strings.Replace(dnsSaveInput, nextTestPassword, "wrong-secret-sentinel", 1), 401},
		{strings.Replace(dnsSaveInput, `"expected_generation":1`, `"expected_generation":2`, 1), 409},
	} {
		w := accountCall(g, "POST", "/api/dns/cloudflare/save", tc.body, cookie, "http://"+localHost, true)
		if w.Code != tc.want || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("reauth/stale not refused")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("refusal wrote token")
		}
	}
	g.derive <- struct{}{}
	if w := accountCall(g, "POST", "/api/dns/cloudflare/save", dnsSaveInput, cookie, "http://"+localHost, true); w.Code != 503 {
		t.Fatal("shared crypto limit bypassed")
	}
	<-g.derive
	w = accountCall(g, "POST", "/api/dns/cloudflare/save", dnsSaveInput, cookie, "http://"+localHost, true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.State != "saved" || result.Generation != 2 || result.NetworkUsed || result.TokenVerified || result.DNSChanged || strings.Contains(w.Body.String(), "synthetic-only-credential") || strings.Contains(w.Body.String(), nextTestPassword) || strings.Contains(w.Body.String(), "0123456789abcdef") {
		t.Fatal("credential save failed/leaked/granted authority")
	}
	w = accountCall(g, "POST", "/api/dns/cloudflare/status", dnsStatusInput, cookie, "http://"+localHost, true)
	var again dnsConfigOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &again) != nil || again != result {
		t.Fatal("saved credential status changed")
	}
	w = accountCall(g, "POST", "/api/dns/cloudflare/remove", dnsRemoveInput, cookie, "http://"+localHost, true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Generation != 3 || result.State != "not-configured" {
		t.Fatal("explicit fresh-auth removal failed")
	}
	if w := accountCall(g, "POST", "/api/dns/cloudflare/save", dnsSaveInput, cookie, "http://"+localHost, true); w.Code != 429 {
		t.Fatal("shared auth budget bypassed")
	}
}

func TestLinuxCloudflareConfigLogoutCancellationAndFetchMetadataCannotWrite(t *testing.T) {
	for _, boundary := range []string{"logout", "cancel", "missing-fetch-metadata"} {
		t.Run(boundary, func(t *testing.T) {
			g, cookie, path := accountGateFixture(t)
			before, _ := os.ReadFile(path)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := &acmeReadHook{Reader: strings.NewReader(dnsSaveInput), onRead: func() {
				if boundary == "cancel" {
					cancel()
				}
				if boundary == "logout" {
					call(g, "DELETE", "/api/session", "", cookie)
				}
			}}
			r := httptest.NewRequest("POST", "http://"+localHost+"/api/dns/cloudflare/save", body).WithContext(ctx)
			r.AddCookie(cookie)
			r.Header.Set("Origin", "http://"+localHost)
			r.Header.Set("X-Rootwell-Request", "1")
			r.Header.Set("Content-Type", "application/json")
			if boundary != "missing-fetch-metadata" {
				r.Header.Set("Sec-Fetch-Site", "same-origin")
			}
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code < 400 || strings.Contains(w.Body.String(), "synthetic-only-credential") {
				t.Fatal("revoked credential request succeeded/leaked")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("revoked request wrote credential")
			}
		})
	}
}
