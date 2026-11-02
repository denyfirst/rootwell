package acmestaging

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmecertificate"
	"github.com/denyfirst/rootwell/internal/acmecertrequest"
	"github.com/denyfirst/rootwell/internal/acmeorder"
)

const testCertificateURL = acmeorder.Origin + "/acme/cert/test-only-1234"

type certificateCalls struct{ all, order, auth, finalize, cert, nonce atomic.Int32 }

func certificateOrderReply(state string) string {
	body := strings.Replace(orderReply(), `"status":"pending"`, `"status":"`+state+`"`, 1)
	if state == "valid" {
		body = strings.TrimSuffix(body, "}") + `,"certificate":"` + testCertificateURL + `"}`
	}
	return body
}

func expiredCertificateOrderReply(state string) string {
	var fields map[string]any
	_ = json.Unmarshal([]byte(certificateOrderReply(state)), &fields)
	fields["expires"] = "2020-01-01T00:00:00Z"
	body, _ := json.Marshal(fields)
	return string(body)
}

func certificateFixture(t *testing.T) (private, csr, der, publicPEM []byte) {
	t.Helper()
	private, csr, _, err := acmecertrequest.Create(testOrderNames)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(private) })
	request, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		t.Fatal(err)
	}
	issuer := testAccountSigner(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(5), DNSNames: slices.Clone(testOrderNames), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err = x509.CreateCertificate(rand.Reader, template, template, request.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return private, csr, der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Independently verify the maintained client's actual account-bound JWS.
func verifyCertificateJWS(t *testing.T, r *http.Request, key *ecdsa.PrivateKey, csr []byte, finalize bool) {
	t.Helper()
	body, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	if err != nil {
		t.Error(err)
		return
	}
	var e map[string]string
	if json.Unmarshal(body, &e) != nil || len(e) != 3 {
		t.Error("invalid certificate JWS")
		return
	}
	protected, _ := base64.RawURLEncoding.DecodeString(e["protected"])
	var h map[string]string
	if json.Unmarshal(protected, &h) != nil || len(h) != 4 || h["kid"] != testAccountURL || h["url"] != acmeorder.Origin+r.URL.Path || h["alg"] != "ES256" || h["nonce"] != testNonce || r.Host != host || r.TLS.ServerName != host {
		t.Error("certificate JWS scope differs")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(e["payload"])
	if finalize {
		var fields map[string]string
		if json.Unmarshal(payload, &fields) != nil || len(fields) != 1 || fields["csr"] != base64.RawURLEncoding.EncodeToString(csr) {
			t.Error("finalize did not send exact CSR only")
		}
	} else if len(payload) != 0 {
		t.Error("read-only certificate request carried a write")
	}
	sig, _ := base64.RawURLEncoding.DecodeString(e["signature"])
	sum := sha256.Sum256([]byte(e["protected"] + "." + e["payload"]))
	if len(sig) != 64 || !ecdsa.Verify(&key.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("certificate JWS signature failed")
	}
}

func certificateServer(t *testing.T, key *ecdsa.PrivateKey, csr, publicPEM []byte, initial, final string, override func(string, http.ResponseWriter, *http.Request) bool) (dependencies, *certificateCalls) {
	t.Helper()
	calls := &certificateCalls{}
	deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
		calls.all.Add(1)
		kind := ""
		switch r.Method + " " + r.URL.Path {
		case "GET /directory":
			kind = "directory"
		case "HEAD /acme/new-nonce":
			kind = "nonce"
			calls.nonce.Add(1)
		case "POST /acme/order/1234/5678":
			kind = "order"
			calls.order.Add(1)
		case "POST /acme/authz-v3/1234/100", "POST /acme/authz-v3/1234/101":
			kind = "authorization"
			calls.auth.Add(1)
		case "POST /acme/finalize/1234/5678":
			kind = "finalize"
			calls.finalize.Add(1)
		case "POST /acme/cert/test-only-1234":
			kind = "certificate"
			calls.cert.Add(1)
		default:
			t.Error("unapproved certificate endpoint reached")
			w.WriteHeader(404)
			return
		}
		if r.Method == "POST" {
			verifyCertificateJWS(t, r, key, csr, kind == "finalize")
		}
		if override != nil && override(kind, w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Hostile unused links/nonce/retry metadata must not acquire authority.
		w.Header().Set("Link", `<http://127.0.0.1/secret>;rel="alternate"`)
		w.Header().Set("Retry-After", "100000")
		switch kind {
		case "directory":
			_, _ = io.WriteString(w, directoryJSON())
		case "nonce":
			w.Header().Set("Replay-Nonce", testNonce)
			w.WriteHeader(204)
		case "order":
			_, _ = io.WriteString(w, certificateOrderReply(initial))
		case "authorization":
			_, _ = io.WriteString(w, authReply(strings.HasSuffix(r.URL.Path, "101"), true))
		case "finalize":
			_, _ = io.WriteString(w, certificateOrderReply(final))
		case "certificate":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write(publicPEM)
		}
	})
	return deps, calls
}

func runCertificate(t *testing.T, private, csr, publicPEM []byte, refresh bool, initial, final string, override func(string, http.ResponseWriter, *http.Request) bool) (certificateObservation, *certificateCalls, error) {
	t.Helper()
	key := testAccountSigner(t)
	deps, calls := certificateServer(t, key, csr, publicPEM, initial, final, override)
	result, err := certificateOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, testOrderURL, time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05Z"), testOrderNames, private, csr, refresh)
	return result, calls, err
}

func TestCertificateConnectorExactCSRAccountJWSAndReadOnlyReconciliation(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	private, csr, der, publicPEM := certificateFixture(t)
	beforePrivate, beforeCSR := bytes.Clone(private), bytes.Clone(csr)
	defer clear(beforePrivate)
	for _, refresh := range []bool{false, true} {
		initial, finalizes, total := "ready", int32(1), int32(11)
		if refresh {
			initial, finalizes, total = "valid", 0, 9
		}
		result, calls, err := runCertificate(t, private, csr, publicPEM, refresh, initial, "valid", nil)
		if err != nil || result.State != "certificate-received" || !acmeorder.Time(result.Expires) || result.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") || len(result.DER) != 1 || !bytes.Equal(result.DER[0], der) || calls.order.Load() != 1 || calls.auth.Load() != 2 || calls.finalize.Load() != finalizes || calls.cert.Load() != 1 || calls.all.Load() != total {
			t.Fatalf("valid bounded certificate flow refused: %v, %d calls", err, calls.all.Load())
		}
		// Protocol success explicitly does not confer receipt trust.
		if _, err := acmecertificate.Check(private, csr, testOrderNames, result.DER, time.Now()); err == nil {
			t.Fatal("synthetic untrusted CA became receipt trust")
		}
	}
	if !bytes.Equal(private, beforePrivate) || !bytes.Equal(csr, beforeCSR) {
		t.Fatal("caller request material changed")
	}
}

func TestCertificateConnectorProcessingNeverPollsOrRefinalizes(t *testing.T) {
	private, csr, _, publicPEM := certificateFixture(t)
	result, calls, err := runCertificate(t, private, csr, publicPEM, false, "ready", "processing", nil)
	if err != nil || result.State != "processing" || result.DER != nil || calls.order.Load() != 1 || calls.finalize.Load() != 1 || calls.cert.Load() != 0 || calls.nonce.Load() != 4 || calls.all.Load() != 9 {
		t.Fatal("processing polled, re-finalized or claimed issuance")
	}
	for _, state := range []string{"pending", "ready", "processing", "invalid"} {
		result, calls, err := runCertificate(t, private, csr, publicPEM, true, state, "valid", nil)
		if err != nil || result.State != state || result.DER != nil || calls.finalize.Load() != 0 || calls.cert.Load() != 0 || calls.auth.Load() != 0 || calls.all.Load() != 3 {
			t.Fatal("same-order refresh obtained write authority or partial receipt")
		}
	}
}

func TestCertificateConnectorRejectsOrderAndAuthorizationSubstitutionBeforeWrite(t *testing.T) {
	private, csr, _, publicPEM := certificateFixture(t)
	for _, body := range []string{
		certificateOrderReply("valid"), certificateOrderReply("pending"),
		strings.Replace(certificateOrderReply("ready"), "example.com", "wrong.example.com", 1),
		strings.Replace(certificateOrderReply("ready"), testAuthWildcardURL, testAuthURL, 1),
		strings.Replace(certificateOrderReply("ready"), "/acme/finalize/1234/", "/acme/finalize/9999/", 1),
		strings.Replace(certificateOrderReply("ready"), `"status":`, `"Status":`, 1),
		`{"status":"ready","status":"valid"}`, "private-error-sentinel",
	} {
		result, calls, err := runCertificate(t, private, csr, publicPEM, false, "ready", "valid", func(kind string, w http.ResponseWriter, _ *http.Request) bool {
			if kind != "order" {
				return false
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
			return true
		})
		if !errors.Is(err, errRefused) || !reflect.DeepEqual(result, certificateObservation{}) || calls.finalize.Load() != 0 || calls.cert.Load() != 0 || calls.order.Load() != 1 {
			t.Fatal("unsafe order gained write authority")
		}
	}
	for _, body := range []string{
		authReply(false, false), authReply(true, true),
		strings.Replace(authReply(false, true), "example.com", "other.example.com", 1),
		strings.Replace(authReply(false, true), `"status":"valid"`, `"status":"invalid"`, 1),
		strings.Replace(authReply(false, true), `"wildcard":false`, `"Wildcard":false`, 1),
	} {
		result, calls, err := runCertificate(t, private, csr, publicPEM, false, "ready", "valid", func(kind string, w http.ResponseWriter, _ *http.Request) bool {
			if kind != "authorization" {
				return false
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
			return true
		})
		if !errors.Is(err, errRefused) || !reflect.DeepEqual(result, certificateObservation{}) || calls.finalize.Load() != 0 || calls.cert.Load() != 0 {
			t.Fatal("incomplete/wrong authorization gained write authority")
		}
	}
}

func TestCertificateConnectorFinalizationFailureNeverRetriesOrReturnsPartialReceipt(t *testing.T) {
	private, csr, _, publicPEM := certificateFixture(t)
	for _, code := range []int{302, 400, 429, 503} {
		result, calls, err := runCertificate(t, private, csr, publicPEM, false, "ready", "valid", func(kind string, w http.ResponseWriter, _ *http.Request) bool {
			if kind != "finalize" {
				return false
			}
			w.Header().Set("Location", "http://127.0.0.1/secret")
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(code)
			_, _ = io.WriteString(w, `{"type":"urn:ietf:params:acme:error:badNonce","detail":"private-error-sentinel"}`)
			return true
		})
		if !errors.Is(err, errRefused) || !reflect.DeepEqual(result, certificateObservation{}) || calls.finalize.Load() != 1 || calls.order.Load() != 1 || calls.cert.Load() != 0 {
			t.Fatal("failed finalize retried, redirected or returned partial receipt")
		}
	}
	for _, body := range []string{
		certificateOrderReply("ready"), certificateOrderReply("invalid"),
		expiredCertificateOrderReply("processing"), expiredCertificateOrderReply("valid"),
		strings.Replace(certificateOrderReply("valid"), testCertificateURL, "http://127.0.0.1/secret", 1),
		strings.Replace(certificateOrderReply("valid"), testAuthURL, acmeorder.Origin+"/acme/authz/9999", 1),
		strings.Replace(certificateOrderReply("valid"), `"certificate":`, `"Certificate":`, 1),
		strings.Replace(certificateOrderReply("processing"), `"status":"processing"`, `"status":"processing","certificate":"`+testCertificateURL+`"`, 1),
	} {
		result, calls, err := runCertificate(t, private, csr, publicPEM, false, "ready", "valid", func(kind string, w http.ResponseWriter, _ *http.Request) bool {
			if kind != "finalize" {
				return false
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
			return true
		})
		if !errors.Is(err, errRefused) || !reflect.DeepEqual(result, certificateObservation{}) || calls.finalize.Load() != 1 || calls.cert.Load() != 0 || calls.order.Load() != 1 {
			t.Fatal("unsafe finalize response followed a URL or polled")
		}
	}
}

func TestCertificateConnectorStrictPublicPEMAndLimits(t *testing.T) {
	private, csr, der, publicPEM := certificateFixture(t)
	withHeader := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Secret": "sentinel"}, Bytes: der})
	badInputs := [][]byte{
		nil, []byte("secret-sentinel"), append([]byte("garbage\n"), publicPEM...), append(bytes.Clone(publicPEM), []byte("trailing")...),
		append(bytes.Clone(publicPEM), publicPEM...), withHeader,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
		append([]byte("-----BEGIN CERTIFICATE-----\nINVALID!\n"), publicPEM...),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: append(bytes.Clone(der), 0)}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bytes.Repeat([]byte{1}, 48<<10+1)}),
		bytes.Repeat([]byte{'x'}, maxCertificatePEM+1),
	}
	for i, input := range badInputs {
		if out, err := strictCertificatePEM(input); !errors.Is(err, errRefused) || out != nil {
			t.Fatalf("unsafe public PEM accepted or partially returned (case %d)", i)
		}
		result, calls, err := runCertificate(t, private, csr, input, true, "valid", "valid", nil)
		if !errors.Is(err, errRefused) || !reflect.DeepEqual(result, certificateObservation{}) || calls.cert.Load() != 1 || calls.finalize.Load() != 0 {
			t.Fatal("unsafe certificate response accepted/retried")
		}
	}
	if out, err := strictCertificatePEM(append([]byte(" \n"), publicPEM...)); err != nil || len(out) == 0 {
		t.Fatal("valid public PEM refused")
	}
}

func TestCertificateConnectorPreflightCancellationAndRevocation(t *testing.T) {
	private, csr, _, publicPEM := certificateFixture(t)
	key := testAccountSigner(t)
	deps, calls := certificateServer(t, key, csr, publicPEM, "ready", "valid", nil)
	accountPrivate, marshalErr := x509.MarshalPKCS8PrivateKey(key)
	defer clear(accountPrivate)
	accountCSR, csrErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: testOrderNames}, key)
	if marshalErr != nil || csrErr != nil {
		t.Fatal("account reuse fixture failed")
	}
	if _, err := certificateOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, testOrderURL, futureCertificateExpiry(), testOrderNames, accountPrivate, accountCSR, false); !errors.Is(err, errRefused) || calls.all.Load() != 0 {
		t.Fatal("account key reused for a certificate request")
	}
	for _, tc := range []struct {
		account, order, expires string
		names                   []string
		private, csr            []byte
	}{
		{"http://127.0.0.1", testOrderURL, futureCertificateExpiry(), testOrderNames, private, csr},
		{testAccountURL, strings.Replace(testOrderURL, "1234", "9999", 1), futureCertificateExpiry(), testOrderNames, private, csr},
		{testAccountURL, testOrderURL, "2020-01-01T00:00:00Z", testOrderNames, private, csr},
		{testAccountURL, testOrderURL, futureCertificateExpiry(), []string{"other.example.com"}, private, csr},
		{testAccountURL, testOrderURL, futureCertificateExpiry(), testOrderNames, nil, csr},
		{testAccountURL, testOrderURL, futureCertificateExpiry(), testOrderNames, private, append(bytes.Clone(csr), 0)},
	} {
		if r, err := certificateOrder(context.Background(), func() bool { return true }, deps, key, tc.account, tc.order, tc.expires, tc.names, tc.private, tc.csr, false); !errors.Is(err, errRefused) || !reflect.DeepEqual(r, certificateObservation{}) || calls.all.Load() != 0 {
			t.Fatal("preflight failure reached network")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, permit := range []func() bool{nil, func() bool { return false }} {
		if _, err := certificateOrder(context.Background(), permit, deps, key, testAccountURL, testOrderURL, futureCertificateExpiry(), testOrderNames, private, csr, false); !errors.Is(err, errRefused) || calls.all.Load() != 0 {
			t.Fatal("absent permission reached network")
		}
	}
	if _, err := certificateOrder(ctx, func() bool { return true }, deps, key, testAccountURL, testOrderURL, futureCertificateExpiry(), testOrderNames, private, csr, false); !errors.Is(err, errRefused) || calls.all.Load() != 0 {
		t.Fatal("cancelled operation reached network")
	}
	var permitted atomic.Bool
	permitted.Store(true)
	deps, calls = certificateServer(t, key, csr, publicPEM, "ready", "valid", func(kind string, w http.ResponseWriter, _ *http.Request) bool {
		if kind != "finalize" {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, certificateOrderReply("valid"))
		permitted.Store(false)
		return true
	})
	r, err := certificateOrder(context.Background(), permitted.Load, deps, key, testAccountURL, testOrderURL, futureCertificateExpiry(), testOrderNames, private, csr, false)
	if !errors.Is(err, errRefused) || !reflect.DeepEqual(r, certificateObservation{}) || calls.finalize.Load() != 1 || calls.cert.Load() != 0 {
		t.Fatal("late revocation allowed certificate fetch/result")
	}
}

func futureCertificateExpiry() string {
	return time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05Z")
}

func parserCertificateJWS(account, nonce, destination, payload string) []byte {
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": account, "nonce": nonce, "url": destination})
	e, _ := json.Marshal(map[string]string{"protected": base64.RawURLEncoding.EncodeToString(h), "payload": base64.RawURLEncoding.EncodeToString([]byte(payload)), "signature": base64.RawURLEncoding.EncodeToString(make([]byte, 64))})
	return e // parser-only fixture, not a valid cryptographic JWS
}

type certificateRoundTripFunc func(*http.Request) (*http.Response, error)

func (f certificateRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCertificateGuardExactCSRAndDenyByDefault(t *testing.T) {
	_, csr, _, _ := certificateFixture(t)
	destination := strings.Replace(testOrderURL, "/acme/order/", "/acme/finalize/", 1)
	guard := certificateTransport{account: testAccountURL, nonce: testNonce, csr: csr}
	payload := `{"csr":"` + base64.RawURLEncoding.EncodeToString(csr) + `"}`
	if !guard.validJWS(parserCertificateJWS(testAccountURL, testNonce, destination, payload), destination, true) {
		t.Fatal("valid exact CSR envelope refused")
	}
	for _, body := range [][]byte{
		parserCertificateJWS(testAccountURL, testNonce, destination, `{"csr":"different"}`),
		parserCertificateJWS(testAccountURL, testNonce, destination, strings.TrimSuffix(payload, "}")+`,"secret":"sentinel"}`),
		parserCertificateJWS(testAccountURL, testNonce, destination, strings.Replace(payload, `"csr":`, `"CSR":`, 1)),
		parserCertificateJWS(testAccountURL, testNonce, destination, `{"csr":null}`),
		parserCertificateJWS(testAccountURL, "wrong", destination, payload),
		parserCertificateJWS("wrong", testNonce, destination, payload),
		parserCertificateJWS(testAccountURL, testNonce, "wrong", payload),
		[]byte(`{"protected":"!","payload":"","signature":""}`),
	} {
		if guard.validJWS(body, destination, true) {
			t.Fatal("altered CSR/JWS scope gained authority")
		}
	}
	if guard.validJWS(parserCertificateJWS(testAccountURL, testNonce, destination, payload), destination, false) {
		t.Fatal("read-only envelope carried a write")
	}
	for _, tc := range []struct {
		name  string
		alter func(*certificateTransport, *http.Request)
	}{
		{"refresh finalize", func(g *certificateTransport, _ *http.Request) { g.refresh = true }},
		{"incomplete authorizations", func(g *certificateTransport, _ *http.Request) { g.authorized = false }},
		{"repeat finalize", func(g *certificateTransport, _ *http.Request) { g.finalized = true }},
		{"no directory", func(g *certificateTransport, _ *http.Request) { g.directory = false }},
		{"no nonce", func(g *certificateTransport, _ *http.Request) { g.nonce = "" }},
		{"already used", func(g *certificateTransport, _ *http.Request) { g.used[destination] = true }},
		{"processing", func(g *certificateTransport, _ *http.Request) { g.processing = true }},
		{"expired", func(g *certificateTransport, _ *http.Request) { g.expires = "2020-01-01T00:00:00Z" }},
		{"request ceiling", func(g *certificateTransport, _ *http.Request) { g.requests = 23 }},
		{"revoked", func(g *certificateTransport, _ *http.Request) { g.allowed = func() bool { return false } }},
		{"cookie", func(_ *certificateTransport, r *http.Request) { r.Header.Set("Cookie", "sentinel") }},
		{"authorization header", func(_ *certificateTransport, r *http.Request) { r.Header.Set("Authorization", "sentinel") }},
		{"wrong host", func(_ *certificateTransport, r *http.Request) { r.Host = "127.0.0.1" }},
		{"wrong endpoint", func(_ *certificateTransport, r *http.Request) { r.URL.Path = "/acme/new-order" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			g := certificateTransport{base: certificateRoundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errRefused }), allowed: func() bool { return true }, account: testAccountURL, order: testOrderURL, expires: futureCertificateExpiry(), nonce: testNonce, csr: csr, directory: true, read: true, authorized: true, used: map[string]bool{}}
			r, err := http.NewRequest("POST", destination, bytes.NewReader(parserCertificateJWS(testAccountURL, testNonce, destination, payload)))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Content-Type", "application/jose+json")
			tc.alter(&g, r)
			if res, err := g.RoundTrip(r); !errors.Is(err, errRefused) || res != nil || calls != 0 || !g.failed {
				t.Fatal("unapproved request reached transport")
			}
			// Even restoring the permission flag cannot reopen this failed lease.
			g.allowed = func() bool { return true }
			g.refresh = false
			g.processing = false
			if _, err := g.RoundTrip(r); !errors.Is(err, errRefused) || calls != 0 {
				t.Fatal("failed operation regained authority")
			}
		})
	}
}

func TestCertificateConnectorHeadersAndLostFinalizeResponse(t *testing.T) {
	private, csr, _, publicPEM := certificateFixture(t)
	for _, tc := range []struct{ kind, header, value string }{
		{"certificate", "Content-Type", "application/json"},
		{"certificate", "Content-Encoding", "gzip"},
		{"certificate", "Content-Type", "application/pem-certificate-chain;other=value"},
		{"certificate", "Content-Length", "99999999"},
		{"finalize", "Location", strings.Replace(testOrderURL, "1234", "9999", 1)},
		{"finalize", "Content-Type", "application/json;charset=latin-1"},
		{"nonce", "Replay-Nonce", "short"},
	} {
		r, calls, err := runCertificate(t, private, csr, publicPEM, false, "ready", "valid", func(kind string, w http.ResponseWriter, _ *http.Request) bool {
			if kind != tc.kind {
				return false
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set(tc.header, tc.value)
			if kind == "certificate" {
				_, _ = w.Write(publicPEM)
			} else if kind == "finalize" {
				_, _ = io.WriteString(w, certificateOrderReply("valid"))
			} else {
				w.WriteHeader(204)
			}
			return true
		})
		if !errors.Is(err, errRefused) || !reflect.DeepEqual(r, certificateObservation{}) || calls.finalize.Load() > 1 || calls.cert.Load() > 1 {
			t.Fatal("unsafe header accepted/retried")
		}
	}
	key := testAccountSigner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var timer atomic.Pointer[time.Timer]
	defer func() {
		if current := timer.Load(); current != nil {
			current.Stop()
		}
	}()
	deps, calls := certificateServer(t, key, csr, publicPEM, "ready", "valid", func(kind string, w http.ResponseWriter, r *http.Request) bool {
		if kind != "finalize" {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		timer.Store(time.AfterFunc(150*time.Millisecond, cancel))
		<-r.Context().Done()
		return true
	})
	r, err := certificateOrder(ctx, func() bool { return true }, deps, key, testAccountURL, testOrderURL, futureCertificateExpiry(), testOrderNames, private, csr, false)
	if !errors.Is(err, errRefused) || !reflect.DeepEqual(r, certificateObservation{}) || calls.finalize.Load() != 1 || calls.order.Load() != 1 || calls.cert.Load() != 0 {
		t.Fatal("lost finalize response replayed or returned partial receipt")
	}
}

func TestCertificatePEMChainCountBoundary(t *testing.T) {
	input := []byte{}
	for i := 0; i < 6; i++ {
		_, _, _, part := certificateFixture(t)
		input = append(input, part...)
		out, err := strictCertificatePEM(input)
		if i < 5 && (err != nil || !bytes.Equal(out, input)) {
			t.Fatal("valid bounded public collection refused")
		}
		if i == 5 && (!errors.Is(err, errRefused) || out != nil) {
			t.Fatal("upstream five-certificate ceiling exceeded")
		}
	}
}

func TestCertificateConnectorMaximumNamesFitExactRequestBudget(t *testing.T) {
	names, urls := []string{}, []string{}
	for i := 0; i < 8; i++ {
		names = append(names, fmt.Sprintf("host%d.example.com", i))
		urls = append(urls, fmt.Sprintf("%s/acme/authz-v3/1234/%d", acmeorder.Origin, 100+i))
	}
	private, csr, _, err := acmecertrequest.Create(names)
	defer clear(private)
	if err != nil {
		t.Fatal(err)
	}
	key := testAccountSigner(t)
	request, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(99), DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, request.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for _, refresh := range []bool{false, true} {
		var count, finalizes atomic.Int32
		deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if r.Method == "POST" {
				verifyCertificateJWS(t, r, key, csr, strings.Contains(r.URL.Path, "/finalize/"))
			}
			switch {
			case r.Method == "GET":
				_, _ = io.WriteString(w, directoryJSON())
			case r.Method == "HEAD":
				w.Header().Set("Replay-Nonce", testNonce)
				w.WriteHeader(204)
			case strings.Contains(r.URL.Path, "/authz-v3/"):
				i := slices.Index(urls, acmeorder.Origin+r.URL.Path)
				if i < 0 {
					t.Error("unknown authorization")
					w.WriteHeader(404)
					return
				}
				body, _ := json.Marshal(map[string]any{"identifier": orderIdentifier{Type: "dns", Value: names[i]}, "status": "valid", "expires": futureCertificateExpiry(), "wildcard": false, "challenges": []any{}})
				_, _ = w.Write(body)
			case r.URL.Path == "/acme/cert/test-only-1234":
				w.Header().Set("Content-Type", "application/pem-certificate-chain")
				_, _ = w.Write(publicPEM)
			case r.URL.Path == "/acme/order/1234/5678" || r.URL.Path == "/acme/finalize/1234/5678":
				state, cert := "ready", ""
				if refresh || strings.Contains(r.URL.Path, "/finalize/") {
					state, cert = "valid", testCertificateURL
				}
				if strings.Contains(r.URL.Path, "/finalize/") {
					finalizes.Add(1)
				}
				ids := []orderIdentifier{}
				for _, name := range names {
					ids = append(ids, orderIdentifier{Type: "dns", Value: name})
				}
				body, _ := json.Marshal(struct {
					Status         string            `json:"status"`
					Expires        string            `json:"expires"`
					Identifiers    []orderIdentifier `json:"identifiers"`
					Authorizations []string          `json:"authorizations"`
					Finalize       string            `json:"finalize"`
					Certificate    string            `json:"certificate,omitempty"`
				}{state, futureCertificateExpiry(), ids, urls, strings.Replace(testOrderURL, "/acme/order/", "/acme/finalize/", 1), cert})
				_, _ = w.Write(body)
			default:
				t.Error("unapproved budget endpoint")
				w.WriteHeader(404)
			}
		})
		result, err := certificateOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, testOrderURL, futureCertificateExpiry(), names, private, csr, refresh)
		want, write := int32(23), int32(1)
		if refresh {
			want, write = 21, 0
		}
		if err != nil || result.State != "certificate-received" || count.Load() != want || finalizes.Load() != write {
			t.Fatalf("max-name flow refused/budget wrong: %v calls %d", err, count.Load())
		}
	}
}

func TestCertificateConnectorInheritsPublicDNSAndTLSTrustRefusal(t *testing.T) {
	private, csr, _, publicPEM := certificateFixture(t)
	for _, poisonTLS := range []bool{false, true} {
		key := testAccountSigner(t)
		deps, calls := certificateServer(t, key, csr, publicPEM, "ready", "valid", nil)
		if poisonTLS {
			deps.tls = deps.tls.Clone()
			deps.tls.RootCAs = x509.NewCertPool()
		} else {
			deps.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
		}
		result, err := certificateOrder(context.Background(), func() bool { return true }, deps, key, testAccountURL, testOrderURL, futureCertificateExpiry(), testOrderNames, private, csr, false)
		if !errors.Is(err, errRefused) || !reflect.DeepEqual(result, certificateObservation{}) || calls.all.Load() != 0 {
			t.Fatal("private DNS/untrusted TLS reached application request")
		}
	}
}

func FuzzCertificateCAResponse(f *testing.F) {
	f.Add([]byte(certificateOrderReply("ready")), uint8(0))
	f.Add([]byte(certificateOrderReply("valid")), uint8(1))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"), uint8(2))
	f.Add(parserCertificateJWS(testAccountURL, testNonce, testCertificateURL, ""), uint8(3))
	f.Fuzz(func(t *testing.T, input []byte, mode uint8) {
		if len(input) > maxCertificatePEM+1 {
			return
		}
		if mode%4 == 2 {
			out, err := strictCertificatePEM(input)
			if err != nil && out != nil {
				t.Fatal("partial public response")
			}
			return
		}
		if mode%4 == 3 {
			guard := certificateTransport{account: testAccountURL, nonce: testNonce, csr: []byte("test-only-public-request")}
			_ = guard.validJWS(input, testCertificateURL, false)
			_ = guard.validJWS(input, testCertificateURL, true)
			return
		}
		guard := certificateTransport{account: testAccountURL, order: testOrderURL, names: slices.Clone(testOrderNames), expires: futureCertificateExpiry(), refresh: true}
		out, err := guard.readOrder(input, false)
		if err != nil && out != nil {
			t.Fatal("partial order response")
		}
		if err == nil && !strictObject(out) {
			t.Fatal("unsafe sanitized order")
		}
	})
}
