package acmestaging

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testTerms = "https://letsencrypt.org/documents/terms.pdf"
const testAccountURL = "https://" + host + "/acme/acct/1234"
const testNonce = "dGVzdC1vbmx5LW5vbmNlLXZhbHVlLTAxMjM0NTY3ODk"

func testAccountSigner(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func verifyRegistrationJWS(t *testing.T, r *http.Request, key *ecdsa.PrivateKey, lookup bool) {
	t.Helper()
	if r.Host != host || r.TLS.ServerName != host || r.Header.Get("Content-Type") != "application/jose+json" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Encoding") != "" {
		t.Error("unexpected request authority")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(body) > 4096 {
		t.Fatal("unbounded JWS")
	}
	var envelope map[string]string
	if json.Unmarshal(body, &envelope) != nil || len(envelope) != 3 {
		t.Fatal("invalid JWS envelope")
	}
	protected, _ := base64.RawURLEncoding.DecodeString(envelope["protected"])
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var header struct {
		Alg   string
		Nonce string
		URL   string
		JWK   struct{ Kty, Crv, X, Y string }
	}
	if json.Unmarshal(protected, &header) != nil || header.Alg != "ES256" || header.Nonce != testNonce || header.URL != registerURL || header.JWK.Kty != "EC" || header.JWK.Crv != "P-256" || header.JWK.X != base64.RawURLEncoding.EncodeToString(public[1:33]) || header.JWK.Y != base64.RawURLEncoding.EncodeToString(public[33:65]) {
		t.Fatal("JWS not bound to stored key/nonce/destination")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(envelope["payload"])
	var fields map[string]bool
	if json.Unmarshal(payload, &fields) != nil || len(fields) != 1 || (lookup && !fields["onlyReturnExisting"]) || (!lookup && !fields["termsOfServiceAgreed"]) {
		t.Fatal("unexpected registration payload authority")
	}
	sig, _ := base64.RawURLEncoding.DecodeString(envelope["signature"])
	digest := sha256.Sum256([]byte(envelope["protected"] + "." + envelope["payload"]))
	if len(sig) != 64 || !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("real library JWS signature failed verification")
	}
}

func accountServer(t *testing.T, key *ecdsa.PrivateKey, lookup bool, account func(http.ResponseWriter, *http.Request)) (dependencies, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.Method + " " + r.URL.Path {
		case "GET /directory":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, directoryJSON())
		case "HEAD /acme/new-nonce":
			w.Header().Set("Replay-Nonce", testNonce)
			w.WriteHeader(204)
		case "POST /acme/new-acct":
			verifyRegistrationJWS(t, r, key, lookup)
			account(w, r)
		default:
			t.Error("unapproved network request")
			w.WriteHeader(404)
		}
	})
	return deps, &requests
}

func validAccountReply(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", testAccountURL)
	w.WriteHeader(code)
	_, _ = io.WriteString(w, `{"status":"valid","contact":[],"orders":"https://`+host+`/acme/orders/1234","termsOfServiceAgreed":true,"createdAt":"ignored","extension":{"never":"followed"}}`)
}

func TestRegistrationUsesRealSameKeyJWSAndOnlyThreePinnedRequests(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	for _, lookup := range []bool{false, true} {
		for _, code := range []int{200, 201} {
			if lookup && code == 201 {
				continue
			}
			key := testAccountSigner(t)
			deps, calls := accountServer(t, key, lookup, func(w http.ResponseWriter, _ *http.Request) { validAccountReply(w, code) })
			uri, absent, err := registerAccount(context.Background(), func() bool { return true }, deps, key, func() string {
				if lookup {
					return ""
				}
				return testTerms
			}(), lookup)
			if err != nil || absent || uri != testAccountURL || calls.Load() != 3 {
				t.Fatalf("approved account operation failed: lookup=%t code=%d requests=%d absent=%t error=%v", lookup, code, calls.Load(), absent, err)
			}
		}
	}
	deps, calls := accountServer(t, testAccountSigner(t), false, func(http.ResponseWriter, *http.Request) { t.Error("terms preview gained signing authority") })
	terms, err := registrationTerms(context.Background(), func() bool { return true }, deps)
	if err != nil || terms != testTerms || calls.Load() != 1 {
		t.Fatal("valid one-GET terms preview refused")
	}
}

func TestRegistrationTermsMismatchRefusesBeforeNonceAndPOST(t *testing.T) {
	key := testAccountSigner(t)
	deps, calls := accountServer(t, key, false, func(http.ResponseWriter, *http.Request) { t.Error("changed terms were accepted") })
	uri, absent, err := registerAccount(context.Background(), func() bool { return true }, deps, key, "https://letsencrypt.org/documents/changed.pdf", false)
	if err == nil || uri != "" || absent || calls.Load() != 1 {
		t.Fatal("changed terms led to signing/registration")
	}
	for _, terms := range []string{"", "https://evil.invalid/terms", "http://letsencrypt.org/documents/terms.pdf", testTerms + "?secret=x", "https://letsencrypt.org/documents/../terms.pdf", "https://letsencrypt.org/documents/%74erms.pdf"} {
		before := calls.Load()
		if _, _, err := registerAccount(context.Background(), func() bool { return true }, deps, key, terms, false); err == nil || calls.Load() != before {
			t.Fatal("unsafe terms acquired network authority")
		}
	}
}

func TestRegistrationStrictAbsentReconciliationNeverCreates(t *testing.T) {
	key := testAccountSigner(t)
	deps, calls := accountServer(t, key, true, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"type":"urn:ietf:params:acme:error:accountDoesNotExist","status":400,"detail":"secret-sentinel","instance":"http://127.0.0.1"}`)
	})
	uri, absent, err := registerAccount(context.Background(), func() bool { return true }, deps, key, "", true)
	if err != nil || !absent || uri != "" || calls.Load() != 3 {
		t.Fatal("absence not safely classified")
	}
}

func TestRegistrationRefusesMalformedForeignAndUncertainAccountWithoutRetry(t *testing.T) {
	for _, tc := range []struct {
		body, location, media string
		code                  int
	}{
		{`{"status":"deactivated"}`, testAccountURL, "application/json", 201},
		{`{"status":"valid","status":"valid"}`, testAccountURL, "application/json", 201},
		{`{"status":"valid","Status":"valid"}`, testAccountURL, "application/json", 201},
		{`{"status":"valid"}`, "http://127.0.0.1/acme/acct/1", "application/json", 201},
		{`{"status":"valid"}`, testAccountURL + "?x=1", "application/json", 201},
		{`{"status":"valid","orders":"https://evil.invalid/orders"}`, testAccountURL, "application/json", 201},
		{`{"status":"valid","contact":["mailto:unexpected@example.com"]}`, testAccountURL, "application/json", 201},
		{`{"status":"valid","termsOfServiceAgreed":false}`, testAccountURL, "application/json", 201},
		{`{"status":"valid"}`, testAccountURL, "application/jsonp", 201},
		{`{"status":"valid"}{}`, testAccountURL, "application/json", 201},
		{strings.Repeat("x", maxBody+1), testAccountURL, "application/json", 201},
		{`{"type":"urn:ietf:params:acme:error:badNonce","detail":"secret-sentinel"}`, testAccountURL, "application/problem+json", 400},
		{`{"type":"urn:ietf:params:acme:error:rateLimited","detail":"secret-sentinel"}`, testAccountURL, "application/problem+json", 429},
		{`{"detail":"secret-sentinel"}`, testAccountURL, "application/json", 503},
		{`{"status":"valid"}`, testAccountURL, "application/json", 302},
	} {
		key := testAccountSigner(t)
		deps, calls := accountServer(t, key, false, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", tc.media)
			w.Header().Set("Location", tc.location)
			w.WriteHeader(tc.code)
			_, _ = io.WriteString(w, tc.body)
		})
		uri, absent, err := registerAccount(context.Background(), func() bool { return true }, deps, key, testTerms, false)
		if err == nil || uri != "" || absent || calls.Load() != 3 || strings.Contains(err.Error(), "secret-sentinel") {
			t.Fatal("malformed/uncertain account accepted, retried or reflected")
		}
	}
}

func TestRegistrationRefusesUnsafeDirectoryNonceAndLostAuthority(t *testing.T) {
	key := testAccountSigner(t)
	for _, body := range []string{strings.Replace(directoryJSON(), "terms.pdf", "../terms.pdf", 1), strings.Replace(directoryJSON(), "new-nonce", "orders", 1), strings.Replace(directoryJSON(), `"termsOfService":`, `"externalAccountRequired":true,"termsOfService":`, 1), strings.Replace(directoryJSON(), `"termsOfService":`, `"TermsOfService":"https://evil.invalid","termsOfService":`, 1)} {
		var count atomic.Int32
		deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			if r.URL.Path != "/directory" {
				t.Error("unsafe directory gained request authority")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		})
		if _, _, err := registerAccount(context.Background(), func() bool { return true }, deps, key, testTerms, false); err == nil || count.Load() != 1 {
			t.Fatal("unsafe directory accepted")
		}
	}
	for _, nonce := range []string{"", "short", testNonce + "=", strings.Repeat("a", 1024)} {
		var count atomic.Int32
		deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			if r.URL.Path == "/directory" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, directoryJSON())
			} else if r.Method == "HEAD" {
				w.Header().Set("Replay-Nonce", nonce)
				w.WriteHeader(204)
			} else {
				t.Error("invalid nonce reached POST")
			}
		})
		if _, _, err := registerAccount(context.Background(), func() bool { return true }, deps, key, testTerms, false); err == nil || count.Load() != 2 {
			t.Fatal("unsafe nonce accepted")
		}
	}
	var permitted atomic.Bool
	permitted.Store(true)
	deps, calls := accountServer(t, key, false, func(w http.ResponseWriter, _ *http.Request) { permitted.Store(false); validAccountReply(w, 201) })
	if uri, _, err := registerAccount(context.Background(), permitted.Load, deps, key, testTerms, false); err == nil || uri != "" || calls.Load() != 3 {
		t.Fatal("late revocation published account")
	}
	if _, _, err := registerAccount(context.Background(), nil, deps, key, testTerms, false); err == nil || calls.Load() != 3 {
		t.Fatal("missing permit dialed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := registerAccount(ctx, func() bool { return true }, deps, key, testTerms, false); err == nil || calls.Load() != 3 {
		t.Fatal("cancelled operation dialed")
	}
	deps.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("DNS-secret-sentinel")
	}
	if _, _, err := registerAccount(context.Background(), func() bool { return true }, deps, key, testTerms, false); err == nil || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatal("DNS refusal reflected")
	}
}

func TestRegistrationParentDeadlineBoundsStalledAccountBody(t *testing.T) {
	key := testAccountSigner(t)
	deps, _ := accountServer(t, key, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", testAccountURL)
		w.WriteHeader(201)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := registerAccount(ctx, func() bool { return true }, deps, key, testTerms, false); err == nil || time.Since(start) > 2*time.Second {
		t.Fatal("stalled response escaped deadline")
	}
}

func FuzzStagingRegistrationResponse(f *testing.F) {
	for _, seed := range []string{`{"status":"valid"}`, `{"type":"urn:ietf:params:acme:error:accountDoesNotExist","status":400}`, directoryJSON()} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > maxBody+1 {
			return
		}
		if strictObject(body) {
			_ = validAccountResponse(body, testAccountURL)
			_ = validAbsentAccount(body)
			_ = validRegistrationMeta(body)
		}
	})
}
