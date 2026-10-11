package acmestaging

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"golang.org/x/crypto/acme"
)

func validationAuth(wildcard bool, status string) string {
	body := authReply(wildcard, status == "valid")
	if wildcard {
		body = strings.ReplaceAll(body, "/chall/1234/100/", "/chall/1234/101/")
	}
	if status != "pending" && status != "valid" {
		body = strings.Replace(body, `"status":"pending"`, `"status":"`+status+`"`, 1)
	}
	return body
}
func validationSaved(t *testing.T, key *ecdsa.PrivateKey) acmeorder.Instructions {
	t.Helper()
	client := acme.Client{Key: key}
	info := acmeorder.Instructions{URL: testOrderURL, Expires: time.Now().UTC().Add(20 * time.Minute).Format("2006-01-02T15:04:05Z")}
	for _, name := range testOrderNames {
		token := testDNSToken
		if strings.HasPrefix(name, "*.") {
			token = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 24))
		}
		digest, err := client.DNS01ChallengeRecord(token)
		if err != nil {
			t.Fatal(err)
		}
		info.Records = append(info.Records, acmeorder.TXT{Domain: name, Name: "_acme-challenge.example.com", Value: digest, Required: true})
	}
	return info
}

func validationServer(t *testing.T, key *ecdsa.PrivateKey, orderStatus string, auth func(bool) string, acceptReply func(string) string) (dependencies, *atomic.Int32) {
	t.Helper()
	accepts, auths := &atomic.Int32{}, &atomic.Int32{}
	deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /directory":
			_, _ = io.WriteString(w, directoryJSON())
			return
		case "HEAD /acme/new-nonce":
			w.Header().Set("Replay-Nonce", testNonce)
			w.WriteHeader(204)
			return
		}
		if r.Method != "POST" {
			t.Error("unapproved method")
			w.WriteHeader(404)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/acme/chall/") {
			accepts.Add(1)
			if auths.Load() != 2 {
				t.Error("acceptance before complete authorization binding")
			}
			body, _ := io.ReadAll(r.Body)
			var e map[string]string
			_ = json.Unmarshal(body, &e)
			payload, _ := base64.RawURLEncoding.DecodeString(e["payload"])
			header, _ := base64.RawURLEncoding.DecodeString(e["protected"])
			var h map[string]string
			_ = json.Unmarshal(header, &h)
			sig, _ := base64.RawURLEncoding.DecodeString(e["signature"])
			hash := sha256.Sum256([]byte(e["protected"] + "." + e["payload"]))
			if string(payload) != "{}" || h["kid"] != testAccountURL || h["url"] != acmeorder.Origin+r.URL.Path || h["nonce"] != testNonce || h["alg"] != "ES256" || len(h) != 4 || len(e) != 3 || len(sig) != 64 || !ecdsa.Verify(&key.PublicKey, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				t.Error("Accept JWS not exact account-bound empty JSON")
			}
			if acceptReply != nil {
				_, _ = io.WriteString(w, acceptReply(r.URL.Path))
				return
			}
			token := testDNSToken
			if strings.Contains(r.URL.Path, "/101/") {
				token = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 24))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"type": "dns-01", "url": acmeorder.Origin + r.URL.Path, "token": token, "status": "processing"})
			return
		}
		verifyOrderJWS(t, r, key, false)
		switch r.URL.Path {
		case "/acme/order/1234/5678":
			_, _ = io.WriteString(w, strings.Replace(orderReply(), `"status":"pending"`, `"status":"`+orderStatus+`"`, 1))
		case "/acme/authz-v3/1234/100", "/acme/authz-v3/1234/101":
			auths.Add(1)
			_, _ = io.WriteString(w, auth(strings.HasSuffix(r.URL.Path, "101")))
		default:
			t.Error("new order/finalize/foreign endpoint reached")
			w.WriteHeader(404)
		}
	})
	return deps, accepts
}

func TestDNSValidationAcceptsOnlyCompleteAcknowledgedScopeAndRefreshNeverWrites(t *testing.T) {
	key := testAccountSigner(t)
	saved := validationSaved(t, key)
	for _, refresh := range []bool{false, true} {
		deps, accepts := validationServer(t, key, "pending", func(w bool) string { return validationAuth(w, "pending") }, nil)
		result, err := dnsValidation(context.Background(), func() bool { return true }, deps, key, testAccountURL, saved, testOrderNames, refresh)
		want := int32(2)
		if refresh {
			want = 0
		}
		if err != nil || accepts.Load() != want || result.Expires != saved.Expires || acmeorder.ValidationState(result, testOrderNames) != "validation-waiting" {
			t.Fatalf("bounded flow refused: %v accepts %d", err, accepts.Load())
		}
	}
	for _, orderStatus := range []string{"pending", "ready", "invalid"} {
		deps, accepts := validationServer(t, key, orderStatus, func(w bool) string { return validationAuth(w, "valid") }, nil)
		result, err := dnsValidation(context.Background(), func() bool { return true }, deps, key, testAccountURL, saved, testOrderNames, true)
		want := map[string]string{"pending": "validation-waiting", "ready": "domain-verified", "invalid": "validation-failed"}[orderStatus]
		if err != nil || accepts.Load() != 0 || acmeorder.ValidationState(result, testOrderNames) != want {
			t.Fatal("order and ALL authorization evidence not required")
		}
	}
}

func TestDNSValidationRejectsChangedOrPartialScopeBeforeAnyAccept(t *testing.T) {
	key := testAccountSigner(t)
	saved := validationSaved(t, key)
	for _, auth := range []func(bool) string{
		func(w bool) string {
			if w {
				return strings.Replace(validationAuth(w, "pending"), `"example.com"`, `"evil.example.com"`, 1)
			}
			return validationAuth(w, "pending")
		},
		func(w bool) string {
			if w {
				return strings.Replace(validationAuth(w, "pending"), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 24)), testDNSToken, 1)
			}
			return validationAuth(w, "pending")
		},
		func(w bool) string {
			return strings.ReplaceAll(validationAuth(w, "pending"), "/chall/1234/101/", "/chall/1234/100/")
		},
		func(bool) string { return validationAuth(false, "pending") },
		func(w bool) string {
			return strings.Replace(validationAuth(w, "pending"), `"wildcard":`, `"Wildcard":`, 1)
		},
	} {
		deps, accepts := validationServer(t, key, "pending", auth, nil)
		result, err := dnsValidation(context.Background(), func() bool { return true }, deps, key, testAccountURL, saved, testOrderNames, false)
		if err == nil || result.URL != "" || accepts.Load() != 0 {
			t.Fatal("changed or partial authorization accepted")
		}
	}
	deps, accepts := validationServer(t, key, "ready", func(w bool) string { return validationAuth(w, "pending") }, nil)
	if _, err := dnsValidation(context.Background(), func() bool { return true }, deps, key, testAccountURL, saved, testOrderNames, false); err == nil || accepts.Load() != 0 {
		t.Fatal("inconsistent ready order accepted")
	}
}

func TestDNSValidationMalformedAcceptClosesAuthorityWithoutRetryOrPartialOutput(t *testing.T) {
	key := testAccountSigner(t)
	saved := validationSaved(t, key)
	for _, body := range []string{`{"type":"dns-01","type":"dns-01"}`, `{"type":"dns-01","url":"http://127.0.0.1","status":"valid","token":"sentinel"}`, `{"Type":"dns-01"}`, "CA-secret-sentinel", strings.Repeat(" ", maxBody+1)} {
		deps, accepts := validationServer(t, key, "pending", func(w bool) string { return validationAuth(w, "pending") }, func(string) string { return body })
		result, err := dnsValidation(context.Background(), func() bool { return true }, deps, key, testAccountURL, saved, testOrderNames, false)
		if err == nil || result.URL != "" || accepts.Load() != 1 || strings.Contains(err.Error(), "sentinel") {
			t.Fatal("malformed Accept retried/leaked/published")
		}
	}
	deps, accepts := validationServer(t, key, "pending", func(w bool) string { return validationAuth(w, "pending") }, nil)
	if _, err := dnsValidation(context.Background(), func() bool { return false }, deps, key, testAccountURL, saved, testOrderNames, false); err == nil || accepts.Load() != 0 {
		t.Fatal("revoked consent accepted")
	}
}

func TestValidationChallengeParserNeverReflectsErrorsOrFollowsURLs(t *testing.T) {
	url := acmeorder.Origin + "/acme/chall/1234/100/abc"
	good := `{"type":"dns-01","url":"` + url + `","token":"` + testDNSToken + `","status":"invalid","error":{"detail":"CA-secret-sentinel","url":"http://127.0.0.1"}}`
	clean, err := readValidationChallenge([]byte(good), url, testDNSToken)
	if err != nil || bytes.Contains(clean, []byte("sentinel")) || bytes.Contains(clean, []byte("127.0.0.1")) {
		t.Fatal("error metadata leaked")
	}
	for _, bad := range []string{strings.Replace(good, `"status":"invalid"`, `"status":"valid"`, 1), strings.Replace(good, `"type":`, `"Type":`, 1), strings.Replace(good, testDNSToken, "changed", 1), strings.Replace(good, url, "http://127.0.0.1", 1)} {
		if clean, err := readValidationChallenge([]byte(bad), url, testDNSToken); err == nil || clean != nil {
			t.Fatal("malformed challenge accepted")
		}
	}
}

func TestValidationTransportRestrictsAcceptPayloadDestinationAndBudget(t *testing.T) {
	url := acmeorder.Origin + "/acme/chall/1234/100/abc"
	guard := &orderTransport{account: testAccountURL, nonce: testNonce, order: testOrderURL, validation: true, challenges: map[string]string{url: testDNSToken}}
	encode := func(payload string) []byte {
		header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": testAccountURL, "nonce": testNonce, "url": url})
		body, _ := json.Marshal(map[string]string{"protected": base64.RawURLEncoding.EncodeToString(header), "payload": base64.RawURLEncoding.EncodeToString([]byte(payload)), "signature": base64.RawURLEncoding.EncodeToString(make([]byte, 64))})
		return body
	}
	if !guard.validJWS(encode("{}"), url, false) {
		t.Fatal("exact Accept payload refused")
	}
	for _, payload := range []string{"", `{"keyAuthorization":"sentinel"}`, `{"status":"deactivated"}`, "null", "[]", "{ }"} {
		if guard.validJWS(encode(payload), url, false) {
			t.Fatal("broad challenge signing permitted")
		}
	}
	guard.validation = false
	if guard.validJWS(encode("{}"), url, false) {
		t.Fatal("instruction transport acquired Accept")
	}
	guard.validation = true
	guard.challenges = nil
	if guard.validJWS(encode("{}"), url, false) {
		t.Fatal("unacknowledged destination signed")
	}
	guard.requests = 35
	guard.allowed = func() bool { return true }
	called := false
	guard.base = tripFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, errRefused })
	r, _ := http.NewRequest("HEAD", nonceURL, nil)
	if _, err := guard.RoundTrip(r); err == nil || called {
		t.Fatal("validation request cap bypassed")
	}
}

func TestDNSValidationLateRevocationAndCancellationReleaseNoResult(t *testing.T) {
	key := testAccountSigner(t)
	saved := validationSaved(t, key)
	var permitted atomic.Bool
	permitted.Store(true)
	deps, accepts := validationServer(t, key, "pending", func(w bool) string { return validationAuth(w, "pending") }, func(string) string { permitted.Store(false); return `{"type":"dns-01"}` })
	if result, err := dnsValidation(context.Background(), permitted.Load, deps, key, testAccountURL, saved, testOrderNames, false); err == nil || result.URL != "" || accepts.Load() != 1 {
		t.Fatal("late revoked result/second acceptance released")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps, accepts = validationServer(t, key, "pending", func(w bool) string { return validationAuth(w, "pending") }, func(string) string { cancel(); return `{"type":"dns-01"}` })
	if result, err := dnsValidation(ctx, func() bool { return true }, deps, key, testAccountURL, saved, testOrderNames, false); err == nil || result.URL != "" || accepts.Load() != 1 {
		t.Fatal("cancelled result/second acceptance released")
	}
}
