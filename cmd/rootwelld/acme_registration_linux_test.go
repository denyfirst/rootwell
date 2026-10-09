//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

const apiTerms = "https://letsencrypt.org/documents/terms.pdf"
const apiAccount = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/1234"

func preparedRegistrationGate(t *testing.T) (*gate, *http.Cookie, string, session) {
	t.Helper()
	g, cookie, path := accountGateFixture(t)
	if w := accountCall(g, "POST", "/api/acme/account/prepare", accountPrepareInput, cookie, "http://"+localHost, true); w.Code != 201 {
		t.Fatal("key preparation failed")
	}
	g.mu.Lock()
	s := g.sessions[sha256.Sum256([]byte(cookie.Value))]
	g.mu.Unlock()
	g.registrationTerms = func(_ context.Context, permit func() bool) (string, error) {
		if !permit() {
			return "", errors.New("revoked")
		}
		return apiTerms, nil
	}
	return g, cookie, path, s
}

func registrationProof(t *testing.T, g *gate, cookie *http.Cookie) string {
	t.Helper()
	g.directoryLast = time.Time{}
	w := accountCall(g, "POST", "/api/acme/registration/preview", registrationPreviewInput, cookie, "http://"+localHost, true)
	var result struct {
		Preview    string
		Generation uint64
		Terms      string `json:"terms_url"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Generation != 2 || result.Terms != apiTerms || len(result.Preview) != 43 {
		t.Fatalf("terms preview failed: %d", w.Code)
	}
	return result.Preview
}

func TestLinuxRegistrationReauthPreviewBindingIntentAndReconciliation(t *testing.T) {
	g, cookie, path, s := preparedRegistrationGate(t)
	defer clear(s.dataKey[:])
	// Freeze the gate clock so slow race/KDF runs do not accidentally expire
	// the shared attempt window while this scenario exercises several refusals.
	at := g.now()
	g.now = func() time.Time { return at }
	before, _ := os.ReadFile(path)
	proof := registrationProof(t, g, cookie)
	calls := 0
	g.registrationCreate = func(_ context.Context, permit func() bool, signer crypto.Signer, terms string) (string, bool, error) {
		calls++
		if !permit() || signer == nil || terms != apiTerms {
			t.Fatal("registration authority missing")
		}
		image, _ := os.ReadFile(path)
		status, gen, err := inventorystore.ReadStagingAccount(s.dataKey[:], s.installationID[:], image)
		if err != nil || gen != 3 || status.Registration != "registration-pending" {
			t.Fatal("network authority preceded durable intent")
		}
		return "", false, errors.New("CA-secret-sentinel")
	}
	for _, bad := range []string{strings.Replace(registrationRequest(proof), nextTestPassword, "wrong-secret-sentinel", 1), strings.Replace(registrationRequest(proof), `"expected_generation":2`, `"expected_generation":3`, 1), registrationRequest(strings.Repeat("A", 43))} {
		w := accountCall(g, "POST", "/api/acme/registration/register", bad, cookie, "http://"+localHost, true)
		if w.Code == 200 || calls != 0 || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("invalid authority reached registration")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("refused authority wrote intent")
		}
	}
	w := accountCall(g, "POST", "/api/acme/registration/register", registrationRequest(proof), cookie, "http://"+localHost, true)
	if w.Code != 503 || calls != 1 || strings.Contains(w.Body.String(), "CA-secret-sentinel") {
		t.Fatal("uncertain registration misreported")
	}
	w = accountCall(g, "POST", "/api/acme/account/status", accountStatusInput, cookie, "http://"+localHost, true)
	var pending accountOutput
	_ = json.Unmarshal(w.Body.Bytes(), &pending)
	if w.Code != 200 || pending.Generation != 3 || pending.Registration != "registration-pending" || pending.AccountCreated {
		t.Fatal("pending status lost")
	}
	w = accountCall(g, "POST", "/api/acme/registration/register", registrationRequest(proof), cookie, "http://"+localHost, true)
	if w.Code != 409 || calls != 1 {
		t.Fatal("blind retry created another account")
	}
	finds := 0
	g.registrationFind = func(_ context.Context, permit func() bool, signer crypto.Signer) (string, bool, error) {
		finds++
		if !permit() || signer == nil {
			t.Fatal("lookup unauthorized")
		}
		return apiAccount, false, nil
	}
	// Login, preparation and the three password checks used the five-attempt
	// budget. Reconciliation must refuse first, then work after a real window.
	w = accountCall(g, "POST", "/api/acme/registration/reconcile", registrationReconcileInput, cookie, "http://"+localHost, true)
	if w.Code != 429 || finds != 0 {
		t.Fatal("reconciliation bypassed the shared attempt window")
	}
	at = at.Add(time.Minute + time.Second)
	w = accountCall(g, "POST", "/api/acme/registration/reconcile", registrationReconcileInput, cookie, "http://"+localHost, true)
	if w.Code != 200 || finds != 1 || strings.Contains(w.Body.String(), apiAccount) || strings.Contains(w.Body.String(), apiTerms) {
		t.Fatal("reconciliation failed or released account URL")
	}
	w = accountCall(g, "POST", "/api/acme/account/status", accountStatusInput, cookie, "http://"+localHost, true)
	var ready accountOutput
	_ = json.Unmarshal(w.Body.Bytes(), &ready)
	if ready.Generation != 4 || ready.Registration != "registered" || !ready.AccountCreated || ready.Fingerprint != pending.Fingerprint || ready.CanIssue {
		t.Fatal("registered status dishonest or changed signer")
	}
}

func TestLinuxRegistrationProofIsSingleUseSessionGenerationAndTimeBound(t *testing.T) {
	for _, boundary := range []string{"expired", "backwards", "session", "generation", "preview-refresh"} {
		t.Run(boundary, func(t *testing.T) {
			g, cookie, path, s := preparedRegistrationGate(t)
			defer clear(s.dataKey[:])
			proof := registrationProof(t, g, cookie)
			calls := 0
			g.registrationCreate = func(context.Context, func() bool, crypto.Signer, string) (string, bool, error) {
				calls++
				return apiAccount, false, nil
			}
			switch boundary {
			case "expired":
				at := g.now().Add(6 * time.Minute)
				g.now = func() time.Time { return at }
			case "backwards":
				at := g.now().Add(-time.Minute)
				g.now = func() time.Time { return at }
			case "session":
				cookie = sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
			case "generation":
				image, _ := os.ReadFile(path)
				next, _, err := inventorystore.Append(s.dataKey[:], s.installationID[:], image, readGateDemo(t), "", "service")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, next, 0o600); err != nil {
					t.Fatal(err)
				}
			case "preview-refresh":
				_ = registrationProof(t, g, cookie)
			}
			w := accountCall(g, "POST", "/api/acme/registration/register", registrationRequest(proof), cookie, "http://"+localHost, true)
			if w.Code == 200 || calls != 0 {
				t.Fatal("stale/foreign proof registered")
			}
		})
	}
}

func readGateDemo(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestLinuxRegistrationBudgetsAndConfirmedCreation(t *testing.T) {
	g, cookie, path, s := preparedRegistrationGate(t)
	defer clear(s.dataKey[:])
	proof := registrationProof(t, g, cookie)
	before, _ := os.ReadFile(path)
	calls := 0
	g.registrationCreate = func(_ context.Context, permit func() bool, _ crypto.Signer, terms string) (string, bool, error) {
		calls++
		if !permit() || terms != apiTerms {
			t.Fatal("creation authority lost")
		}
		return apiAccount, false, nil
	}
	g.derive <- struct{}{}
	w := accountCall(g, "POST", "/api/acme/registration/register", registrationRequest(proof), cookie, "http://"+localHost, true)
	<-g.derive
	if w.Code != 503 || calls != 0 {
		t.Fatal("busy derivation granted authority")
	}
	g.mu.Lock()
	g.attempts = nil
	g.mu.Unlock()
	for i := 0; i < 5; i++ {
		if !g.allowAttempt() {
			t.Fatal("test budget unavailable")
		}
	}
	w = accountCall(g, "POST", "/api/acme/registration/register", registrationRequest(proof), cookie, "http://"+localHost, true)
	if w.Code != 429 || calls != 0 {
		t.Fatal("shared password budget bypassed")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("budget refusal wrote intent")
	}
	g.mu.Lock()
	g.attempts = nil
	g.mu.Unlock()
	// A valid preview may be confirmed immediately despite its own cooldown.
	w = accountCall(g, "POST", "/api/acme/registration/register", registrationRequest(proof), cookie, "http://"+localHost, true)
	var result struct {
		Generation uint64
		State      string
		Saved      bool
		CanIssue   bool `json:"can_issue"`
	}
	if w.Code != 200 || calls != 1 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Generation != 4 || result.State != "registered" || !result.Saved || result.CanIssue || strings.Contains(w.Body.String(), apiAccount) {
		t.Fatal("confirmed creation not saved or granted excess authority")
	}
	w = accountCall(g, "POST", "/api/acme/registration/register", registrationRequest(proof), cookie, "http://"+localHost, true)
	if w.Code != 409 || calls != 1 {
		t.Fatal("consumed preview reused after completion")
	}
}

func TestLinuxRegistrationPreviewProviderBusyCooldownAndStoreChange(t *testing.T) {
	g, cookie, path, s := preparedRegistrationGate(t)
	defer clear(s.dataKey[:])
	calls := 0
	g.registrationTerms = func(context.Context, func() bool) (string, error) {
		calls++
		return apiTerms, nil
	}
	g.directoryBusy = true
	w := accountCall(g, "POST", "/api/acme/registration/preview", registrationPreviewInput, cookie, "http://"+localHost, true)
	if w.Code != 429 || calls != 0 {
		t.Fatal("provider overlap accepted")
	}
	g.directoryBusy = false
	g.directoryLast = g.now()
	w = accountCall(g, "POST", "/api/acme/registration/preview", registrationPreviewInput, cookie, "http://"+localHost, true)
	if w.Code != 429 || calls != 0 {
		t.Fatal("provider cooldown bypassed")
	}
	g.directoryLast = time.Time{}
	g.registrationTerms = func(context.Context, func() bool) (string, error) {
		image, _ := os.ReadFile(path)
		next, _, err := inventorystore.Append(s.dataKey[:], s.installationID[:], image, readGateDemo(t), "", "changed during preview")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, next, 0o600); err != nil {
			t.Fatal(err)
		}
		return apiTerms, nil
	}
	w = accountCall(g, "POST", "/api/acme/registration/preview", registrationPreviewInput, cookie, "http://"+localHost, true)
	if w.Code != 409 || g.registrationPreview != nil || strings.Contains(w.Body.String(), apiTerms) {
		t.Fatal("late stale preview granted authority")
	}
}

func TestLinuxRegistrationLogoutAndCancellationLeavePendingNotSuccess(t *testing.T) {
	for _, cancelRequest := range []bool{false, true} {
		g, cookie, path, s := preparedRegistrationGate(t)
		defer clear(s.dataKey[:])
		proof := registrationProof(t, g, cookie)
		entered, release := make(chan struct{}), make(chan struct{})
		g.registrationCreate = func(_ context.Context, permit func() bool, _ crypto.Signer, _ string) (string, bool, error) {
			close(entered)
			<-release
			if permit() {
				t.Error("revoked session still authorized")
			}
			return apiAccount, false, nil
		}
		r := httptest.NewRequest("POST", "http://"+localHost+"/api/acme/registration/register", strings.NewReader(registrationRequest(proof)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://"+localHost)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("X-Rootwell-Request", "1")
		r.AddCookie(cookie)
		ctx, cancel := context.WithCancel(r.Context())
		r = r.WithContext(ctx)
		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { defer close(done); g.ServeHTTP(w, r) }()
		<-entered
		if cancelRequest {
			cancel()
		} else {
			g.revokeSession(httptest.NewRecorder(), r)
		}
		close(release)
		<-done
		cancel()
		if w.Code == 200 {
			t.Fatal("late registration published success")
		}
		image, _ := os.ReadFile(path)
		status, gen, err := inventorystore.ReadStagingAccount(s.dataKey[:], s.installationID[:], image)
		if err != nil || gen != 3 || status.Registration != "registration-pending" {
			t.Fatal("late callback committed account or lost intent")
		}
	}
}
