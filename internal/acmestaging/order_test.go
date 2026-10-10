package acmestaging

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
)

const testOrderURL = acmeorder.Origin + "/acme/order/1234/5678"
const testAuthURL = acmeorder.Origin + "/acme/authz-v3/1234/100"
const testAuthWildcardURL = acmeorder.Origin + "/acme/authz-v3/1234/101"
const testDNSToken = "dGVzdC1vbmx5LXRva2VuLTAxMjM0NTY3ODk"

var testOrderNames = []string{"*.example.com", "example.com"}

func orderReply() string {
	return `{"status":"pending","expires":"` + time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05Z") + `","identifiers":[{"type":"dns","value":"example.com"},{"type":"dns","value":"*.example.com"}],"authorizations":["` + testAuthURL + `","` + testAuthWildcardURL + `"],"finalize":"` + strings.Replace(testOrderURL, "/acme/order/", "/acme/finalize/", 1) + `","extension":{"secret":"never-reflected"}}`
}
func authReply(wildcard, valid bool) string {
	status, token := "pending", testDNSToken
	if valid {
		status = "valid"
	}
	if wildcard {
		token = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 24))
	}
	return fmt.Sprintf(`{"identifier":{"type":"dns","value":"example.com"},"status":%q,"expires":%q,"wildcard":%t,"challenges":[{"type":"dns-01","status":%q,"url":%q,"token":%q},{"type":"http-01","status":"pending","url":%q,"token":%q}]}`, status, time.Now().UTC().Add(30*time.Minute).Format("2006-01-02T15:04:05Z"), wildcard, status, acmeorder.Origin+"/acme/chall/1234/100/abc", token, acmeorder.Origin+"/acme/chall/1234/100/def", testDNSToken)
}
func verifyOrderJWS(t *testing.T, r *http.Request, key *ecdsa.PrivateKey, create bool) {
	t.Helper()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil {
		t.Error(err)
		return
	}
	var envelope map[string]string
	if json.Unmarshal(raw, &envelope) != nil || len(envelope) != 3 {
		t.Error("invalid JWS")
		return
	}
	header, _ := base64.RawURLEncoding.DecodeString(envelope["protected"])
	var h map[string]string
	if json.Unmarshal(header, &h) != nil || len(h) != 4 || h["kid"] != testAccountURL || h["url"] != acmeorder.Origin+r.URL.Path || h["alg"] != "ES256" || h["nonce"] != testNonce || r.Host != host || r.TLS.ServerName != host {
		t.Error("JWS scope differs")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(envelope["payload"])
	if create {
		var w struct{ Identifiers []orderIdentifier }
		if json.Unmarshal(payload, &w) != nil || len(w.Identifiers) != 2 || w.Identifiers[0].Value != testOrderNames[0] || w.Identifiers[1].Value != testOrderNames[1] {
			t.Error("order names differ")
		}
	} else if len(payload) != 0 {
		t.Error("read-only request has write payload")
	}
	sig, _ := base64.RawURLEncoding.DecodeString(envelope["signature"])
	sum := sha256.Sum256([]byte(envelope["protected"] + "." + envelope["payload"]))
	if len(sig) != 64 || !ecdsa.Verify(&key.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("library JWS signature failed")
	}
}

type orderTestServer struct {
	calls atomic.Int32
	posts atomic.Int32
	authz atomic.Int32
}

func orderServer(t *testing.T, key *ecdsa.PrivateKey, orderHandler func(http.ResponseWriter, *http.Request), authHandler func(http.ResponseWriter, *http.Request)) (dependencies, *orderTestServer) {
	t.Helper()
	counts := &orderTestServer{}
	deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
		counts.calls.Add(1)
		switch r.Method + " " + r.URL.Path {
		case "GET /directory":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, directoryJSON())
		case "HEAD /acme/new-nonce":
			w.Header().Set("Replay-Nonce", testNonce)
			w.WriteHeader(204)
		case "POST /acme/new-order", "POST /acme/order/1234/5678":
			counts.posts.Add(1)
			verifyOrderJWS(t, r, key, r.URL.Path == "/acme/new-order")
			orderHandler(w, r)
		case "POST /acme/authz-v3/1234/100", "POST /acme/authz-v3/1234/101":
			counts.authz.Add(1)
			verifyOrderJWS(t, r, key, false)
			authHandler(w, r)
		default:
			t.Error("unapproved endpoint reached")
			w.WriteHeader(404)
		}
	})
	return deps, counts
}
func goodOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/acme/new-order" {
		w.Header().Set("Location", testOrderURL)
		w.WriteHeader(201)
	}
	_, _ = io.WriteString(w, orderReply())
}
func goodAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, authReply(strings.HasSuffix(r.URL.Path, "101"), false))
}

func TestManualDNSOrderUsesAccountBoundJWSAndPreservesBothTXTValues(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	for _, resume := range []bool{false, true} {
		key := testAccountSigner(t)
		deps, calls := orderServer(t, key, goodOrder, goodAuth)
		saved := ""
		order := ""
		if resume {
			order = testOrderURL
		}
		info, err := dnsOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, order, testOrderNames, func(url string) error {
			if calls.authz.Load() != 0 {
				t.Fatal("auth fetched before durable URI")
			}
			saved = url
			return nil
		})
		if err != nil || !acmeorder.ValidInstructions(info, testAccountURL, testOrderNames) || calls.calls.Load() != 7 || calls.posts.Load() != 1 || calls.authz.Load() != 2 || info.Records[0].Name != info.Records[1].Name || info.Records[0].Value == info.Records[1].Value || (!resume && saved != testOrderURL) || (resume && saved != "") {
			t.Fatalf("valid bounded flow refused: %v calls %d", err, calls.calls.Load())
		}
		// Independently calculate the RFC 8555 digest, not by calling the
		// client's DNS helper a second time. Bind it to this account's JWK.
		public, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		jwk := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, base64.RawURLEncoding.EncodeToString(public[1:33]), base64.RawURLEncoding.EncodeToString(public[33:65]))
		thumb := sha256.Sum256([]byte(jwk))
		digest := sha256.Sum256([]byte(testDNSToken + "." + base64.RawURLEncoding.EncodeToString(thumb[:])))
		if info.Records[1].Value != base64.RawURLEncoding.EncodeToString(digest[:]) {
			t.Fatal("TXT digest is not bound to challenge and account public key")
		}
	}
	key := testAccountSigner(t)
	deps, _ := orderServer(t, key, goodOrder, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, authReply(strings.HasSuffix(r.URL.Path, "101"), true))
	})
	info, err := dnsOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, testOrderURL, testOrderNames, nil)
	if err != nil || info.Records[0].Required || info.Records[0].Value != "" {
		t.Fatal("already authorized name got fabricated token")
	}
}

func TestManualDNSOrderCheckpointsBeforeStalledOrMalformedBody(t *testing.T) {
	for _, body := range []string{`{"status":"pending","status":"ready"}`, "private-sentinel", strings.Replace(orderReply(), "example.com", "wrong.example.com", 1), strings.Replace(orderReply(), testAuthURL, "http://127.0.0.1/auth", 1), strings.Replace(orderReply(), "\"finalize\":", "\"Finalize\":", 1)} {
		key := testAccountSigner(t)
		saved := ""
		deps, calls := orderServer(t, key, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", testOrderURL)
			w.WriteHeader(201)
			_, _ = io.WriteString(w, body)
		}, goodAuth)
		info, err := dnsOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, "", testOrderNames, func(url string) error { saved = url; return nil })
		if err == nil || info.URL != "" || saved != testOrderURL || calls.authz.Load() != 0 || calls.posts.Load() != 1 || strings.Contains(err.Error(), "sentinel") {
			t.Fatal("malformed creation lost checkpoint or retried")
		}
	}
	key := testAccountSigner(t)
	saved := ""
	deps, calls := orderServer(t, key, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", testOrderURL)
		w.WriteHeader(201)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}, goodAuth)
	// Allow TLS setup to finish even on a busy race-test runner. Start the
	// short cancellation window only after the URI is actually checkpointed,
	// so this tests a stalled body rather than scheduler/setup performance.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var checkpointed time.Time
	var bodyTimer *time.Timer
	defer func() {
		if bodyTimer != nil {
			bodyTimer.Stop()
		}
	}()
	if _, err := dnsOrder(ctx, func() bool { return true }, deps, key, testAccountURL, "", testOrderNames, func(url string) error {
		saved = url
		checkpointed = time.Now()
		bodyTimer = time.AfterFunc(150*time.Millisecond, cancel)
		return nil
	}); err == nil || saved != testOrderURL || calls.posts.Load() != 1 || checkpointed.IsZero() || time.Since(checkpointed) > 2*time.Second {
		t.Fatal("stalled creation lost URI/deadline")
	}
}

func TestManualDNSOrderRefusesUnsafeLocationFailedCheckpointAndAuthzWithoutRetry(t *testing.T) {
	for _, location := range []string{"", strings.Replace(testOrderURL, "1234", "9999", 1), testOrderURL + "?secret=x", "http://127.0.0.1/order"} {
		key := testAccountSigner(t)
		deps, calls := orderServer(t, key, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", location)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			_, _ = io.WriteString(w, orderReply())
		}, goodAuth)
		if _, err := dnsOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, "", testOrderNames, func(string) error { t.Error("unsafe URI checkpointed"); return nil }); err == nil || calls.posts.Load() != 1 || calls.authz.Load() != 0 {
			t.Fatal("unsafe location accepted")
		}
	}
	key := testAccountSigner(t)
	deps, calls := orderServer(t, key, goodOrder, goodAuth)
	if _, err := dnsOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, "", testOrderNames, func(string) error { return errors.New("checkpoint-sentinel") }); err == nil || calls.posts.Load() != 1 || calls.authz.Load() != 0 {
		t.Fatal("failed checkpoint gained authority")
	}
	for _, body := range []string{strings.Replace(authReply(false, false), "example.com", "wrong.example.com", 1), strings.Replace(authReply(false, false), testDNSToken, "short", 1), strings.Replace(authReply(false, false), "\"wildcard\":false", "\"wildcard\":true", 1), strings.Replace(authReply(false, false), "/acme/chall/", "/arbitrary/", 1), strings.Replace(authReply(false, false), "\"status\":\"pending\"", "\"status\":\"invalid\"", 1), strings.Replace(authReply(false, false), "\"identifier\":", "\"Identifier\":", 1), strings.Replace(authReply(false, false), "\"token\":", "\"Token\":", 1)} {
		key := testAccountSigner(t)
		deps, calls := orderServer(t, key, goodOrder, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		})
		info, err := dnsOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, testOrderURL, testOrderNames, nil)
		if err == nil || info.URL != "" || calls.posts.Load() != 1 || calls.authz.Load() > 2 {
			t.Fatal("unsafe/duplicate authorization yielded instructions")
		}
	}
	for _, code := range []int{302, 400, 429, 503} {
		deps, calls := orderServer(t, key, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.Header().Set("Location", "http://127.0.0.1")
			w.WriteHeader(code)
			_, _ = io.WriteString(w, `{"type":"urn:ietf:params:acme:error:badNonce","detail":"secret-sentinel"}`)
		}, goodAuth)
		if _, err := dnsOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, testOrderURL, testOrderNames, nil); err == nil || calls.posts.Load() != 1 || calls.authz.Load() != 0 {
			t.Fatal("CA refusal redirected/retried")
		}
	}
}

func TestManualDNSOrderPreflightAndLateRevocationRefuseAuthority(t *testing.T) {
	key := testAccountSigner(t)
	deps, calls := orderServer(t, key, goodOrder, goodAuth)
	for _, tc := range []struct {
		account, order string
		names          []string
		permit         func() bool
	}{{testAccountURL, testOrderURL, testOrderNames, nil}, {"https://evil.invalid", testOrderURL, testOrderNames, func() bool { return true }}, {testAccountURL, testOrderURL + "?x=1", testOrderNames, func() bool { return true }}, {testAccountURL, testOrderURL, []string{"example.com", "*.example.com"}, func() bool { return true }}} {
		if _, err := dnsOrder(context.Background(), tc.permit, deps, key, tc.account, tc.order, tc.names, nil); err == nil || calls.calls.Load() != 0 {
			t.Fatal("unapproved scope dialed")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dnsOrder(ctx, func() bool { return true }, deps, key, testAccountURL, testOrderURL, testOrderNames, nil); err == nil || calls.calls.Load() != 0 {
		t.Fatal("cancelled scope dialed")
	}
	var permitted atomic.Bool
	permitted.Store(true)
	deps, calls = orderServer(t, key, goodOrder, func(w http.ResponseWriter, r *http.Request) { goodAuth(w, r); permitted.Store(false) })
	if info, err := dnsOrder(context.Background(), permitted.Load, deps, key, testAccountURL, testOrderURL, testOrderNames, nil); err == nil || info.URL != "" || calls.authz.Load() != 1 {
		t.Fatal("revoked operation published TXT")
	}
}

func TestManualDNSJWSGuardRejectsWritePayloadAndUnapprovedDestination(t *testing.T) {
	tpt := &orderTransport{account: testAccountURL, nonce: testNonce, names: slices.Clone(testOrderNames)}
	encode := func(header map[string]string, payload string) []byte {
		h, _ := json.Marshal(header)
		b, _ := json.Marshal(map[string]string{"protected": base64.RawURLEncoding.EncodeToString(h), "payload": base64.RawURLEncoding.EncodeToString([]byte(payload)), "signature": base64.RawURLEncoding.EncodeToString(make([]byte, 64))})
		return b
	}
	h := map[string]string{"alg": "ES256", "kid": testAccountURL, "url": testOrderURL, "nonce": testNonce}
	if !tpt.validJWS(encode(h, ""), testOrderURL, false) {
		t.Fatal("POST-as-GET refused")
	}
	for _, payload := range []string{`{}`, `{"csr":"AAAA"}`, `{"keyAuthorization":"secret-sentinel"}`} {
		if tpt.validJWS(encode(h, payload), testOrderURL, false) {
			t.Fatal("write payload signed")
		}
	}
	for field, value := range map[string]string{"alg": "RS256", "kid": "https://evil.invalid", "url": newOrderURL, "nonce": "another-nonce"} {
		bad := map[string]string{}
		for k, v := range h {
			bad[k] = v
		}
		bad[field] = value
		if tpt.validJWS(encode(bad, ""), testOrderURL, false) {
			t.Fatal("foreign header signed")
		}
	}
}

func TestManualDNSTransportRefusesUnapprovedMethodsPathsAndBudgetBeforeIO(t *testing.T) {
	for _, tc := range []struct {
		method, url string
		requests    int
		failed      bool
	}{
		{"GET", testOrderURL, 0, false}, {"POST", acmeorder.Origin + "/acme/finalize/1234/5678", 0, false},
		{"POST", acmeorder.Origin + "/acme/chall/1234/100/abc", 0, false}, {"HEAD", nonceURL, 19, false}, {"HEAD", nonceURL, 0, true},
	} {
		called := false
		guard := &orderTransport{base: tripFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, errRefused }), allowed: func() bool { return true }, account: testAccountURL, order: testOrderURL, directory: true, requests: tc.requests, failed: tc.failed, used: map[string]bool{}}
		r, err := http.NewRequest(tc.method, tc.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if response, err := guard.RoundTrip(r); err == nil || response != nil || called {
			t.Fatal("unapproved/budgeted transport performed IO")
		}
	}
}

func FuzzManualDNSCAResponse(f *testing.F) {
	f.Add([]byte(orderReply()))
	f.Add([]byte(authReply(false, false)))
	f.Add([]byte(authReply(true, true)))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > maxBody+1 {
			return
		}
		guard := &orderTransport{order: testOrderURL, names: slices.Clone(testOrderNames)}
		_, _ = guard.readOrder(body)
		_, _ = readOrderAuthorization(body, testOrderNames)
	})
}
