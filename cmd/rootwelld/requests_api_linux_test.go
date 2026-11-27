//go:build linux

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certificatepair"
)

type waitingRequest struct {
	PublicFingerprint string   `json:"public_fingerprint"`
	CSR               string   `json:"csr"`
	DNSNames          []string `json:"dns_names"`
	IPAddresses       []string `json:"ip_addresses"`
	KeyType           string   `json:"key_type"`
	Renews            string   `json:"renews"`
}

type requestList struct {
	Generation uint64           `json:"generation"`
	Requests   []waitingRequest `json:"requests"`
	Records    []struct {
		Fingerprint     string   `json:"fingerprint"`
		Locations       []string `json:"locations"`
		HasPrivateKey   bool     `json:"has_private_key"`
		KeyStatus       string   `json:"key_status"`
		ReplacedBy      string   `json:"replaced_by"`
		Replaces        string   `json:"replaces"`
		Renews          string   `json:"renews"`
		FinishesRequest bool     `json:"finishes_request"`
	} `json:"records"`
}

func readList(t *testing.T, body []byte) requestList {
	t.Helper()
	var out requestList
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("answer: %v: %s", err, body)
	}
	return out
}

func listWithRequests(t *testing.T, e *testEnv, cookie *http.Cookie) requestList {
	t.Helper()
	w := apiCall(e.g, "GET", "/api/inventory", "", cookie, "", true)
	if w.Code != http.StatusOK || bytes.Contains(w.Body.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	return readList(t, w.Body.Bytes())
}

// providerIssues signs a certificate for a request's key, as a provider would.
func providerIssues(t *testing.T, csr string, life time.Duration, names ...string) ([]byte, string) {
	t.Helper()
	block, _ := pem.Decode([]byte(csr))
	if block == nil {
		t.Fatal("the request is not PEM")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		t.Fatalf("the request: %v", err)
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Provider"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(life + time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leaf, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]},
		DNSNames: names, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(life)}, ca, request.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	record, canonical, err := certificatepair.Prepare(leaf, nil, nil, "", "")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, record.Fingerprint
}

func TestLinuxARequestKeepsItsKeyAndItsCertificateFinishesIt(t *testing.T) {
	_, cookie, e := readyGate(t)
	w := post(t, e, cookie, "/api/requests/create", map[string]any{"expected_generation": 1, "algorithm": "ec-p256", "dns_names": []string{"shop.rootwell.invalid"}, "ip_addresses": []string{"10.0.0.7"}, "organization": "Example Ltd", "country": "AZ"})
	if w.code != http.StatusCreated || bytes.Contains(w.body, []byte("PRIVATE KEY")) {
		t.Fatalf("make a request: %d %s", w.code, w.body)
	}
	var made struct {
		Generation uint64         `json:"generation"`
		Request    waitingRequest `json:"request"`
	}
	if err := json.Unmarshal(w.body, &made); err != nil || made.Generation != 2 || made.Request.KeyType != "ECDSA P-256" ||
		!slices.Equal(made.Request.DNSNames, []string{"shop.rootwell.invalid"}) || !slices.Equal(made.Request.IPAddresses, []string{"10.0.0.7"}) {
		t.Fatalf("the request: %+v: %v", made, err)
	}
	list := listWithRequests(t, e, cookie)
	if list.Generation != 2 || len(list.Requests) != 1 || list.Requests[0].CSR != made.Request.CSR || len(list.Records) != 0 {
		t.Fatalf("the list: %+v", list)
	}

	certificate, fingerprint := providerIssues(t, made.Request.CSR, 90*24*time.Hour, "shop.rootwell.invalid")
	check := post(t, e, cookie, "/api/certificates/check", map[string]any{"certificate": certificate, "expected_generation": 2})
	if checked := readList(t, check.body); check.code != 200 || len(checked.Records) != 1 || !checked.Records[0].FinishesRequest || checked.Records[0].HasPrivateKey {
		t.Fatalf("check: %d %s", check.code, check.body)
	}
	if after := listWithRequests(t, e, cookie); after.Generation != 2 || len(after.Requests) != 1 {
		t.Fatalf("a check finished the request: %+v", after)
	}
	saved := post(t, e, cookie, "/api/certificates/save", map[string]any{"certificate": certificate, "expected_generation": 2, "fingerprint": fingerprint})
	if record := readList(t, saved.body); saved.code != 201 || len(record.Records) != 1 || !record.Records[0].HasPrivateKey || record.Records[0].KeyStatus != "matched" {
		t.Fatalf("save: %d %s", saved.code, saved.body)
	}
	if after := listWithRequests(t, e, cookie); after.Generation != 3 || len(after.Requests) != 0 || len(after.Records) != 1 || !after.Records[0].HasPrivateKey {
		t.Fatalf("after saving: %+v", after)
	}
}

func TestLinuxARenewalIsMadeFromTheCertificateAndTakesItsPlace(t *testing.T) {
	_, cookie, e := readyGate(t)
	old, _ := selfSigned(t, "a.rootwell.invalid")
	record, canonical, err := certificatepair.Prepare(old, nil, nil, "", "")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if w := post(t, e, cookie, "/api/certificates/save", map[string]any{"certificate": old, "expected_generation": 1, "fingerprint": record.Fingerprint, "location": "web-1"}); w.code != 201 {
		t.Fatalf("save: %d %s", w.code, w.body)
	}
	if w := post(t, e, cookie, "/api/requests/create", map[string]any{"expected_generation": 2, "algorithm": "ec-p256", "renews": record.Fingerprint, "dns_names": []string{"b.rootwell.invalid"}}); w.code != http.StatusBadRequest {
		t.Fatalf("a renewal with other names: %d %s", w.code, w.body)
	}
	w := post(t, e, cookie, "/api/requests/create", map[string]any{"expected_generation": 2, "algorithm": "rsa-2048", "renews": record.Fingerprint})
	var made struct {
		Request waitingRequest `json:"request"`
	}
	if w.code != http.StatusCreated || json.Unmarshal(w.body, &made) != nil || made.Request.Renews != record.Fingerprint ||
		!slices.Equal(made.Request.DNSNames, []string{"a.rootwell.invalid"}) || made.Request.KeyType != "RSA 2048" {
		t.Fatalf("renew: %d %s", w.code, w.body)
	}
	if again := post(t, e, cookie, "/api/requests/create", map[string]any{"expected_generation": 3, "algorithm": "ec-p256", "renews": record.Fingerprint}); again.code != http.StatusConflict || again.header.Get("X-Rootwell-Refusal") != "renewal-waiting" {
		t.Fatalf("a second renewal: %d %s", again.code, again.body)
	}

	renewed, fingerprint := providerIssues(t, made.Request.CSR, 90*24*time.Hour, "a.rootwell.invalid")
	check := readList(t, post(t, e, cookie, "/api/certificates/check", map[string]any{"certificate": renewed, "expected_generation": 3}).body)
	if len(check.Records) != 1 || !check.Records[0].FinishesRequest || check.Records[0].Renews != record.Fingerprint || check.Records[0].Replaces != "" {
		t.Fatalf("check: %+v", check)
	}
	if w := post(t, e, cookie, "/api/certificates/save", map[string]any{"certificate": renewed, "expected_generation": 3, "fingerprint": fingerprint}); w.code != 201 {
		t.Fatalf("save the renewal: %d %s", w.code, w.body)
	}
	after := listWithRequests(t, e, cookie)
	if len(after.Records) != 2 || len(after.Requests) != 0 {
		t.Fatalf("after the renewal: %+v", after)
	}
	for _, r := range after.Records {
		switch r.Fingerprint {
		case record.Fingerprint:
			if r.ReplacedBy != fingerprint {
				t.Fatalf("the older one is not replaced: %+v", r)
			}
		case fingerprint:
			if r.Replaces != record.Fingerprint || !slices.Equal(r.Locations, []string{"web-1"}) || !r.HasPrivateKey {
				t.Fatalf("the renewal did not take the place: %+v", r)
			}
		}
	}
	if w := post(t, e, cookie, "/api/requests/create", map[string]any{"expected_generation": 4, "algorithm": "ec-p256", "renews": record.Fingerprint}); w.code != http.StatusConflict || w.header.Get("X-Rootwell-Refusal") != "replaced" {
		t.Fatalf("a renewal of a replaced certificate: %d %s", w.code, w.body)
	}
}

func TestLinuxGivingUpARequestNeedsAFreshCode(t *testing.T) {
	_, cookie, e := readyGate(t)
	w := post(t, e, cookie, "/api/requests/create", map[string]any{"expected_generation": 1, "algorithm": "ec-p256", "dns_names": []string{"shop.rootwell.invalid"}})
	var made struct {
		Request waitingRequest `json:"request"`
	}
	if w.code != http.StatusCreated || json.Unmarshal(w.body, &made) != nil {
		t.Fatalf("make a request: %d %s", w.code, w.body)
	}
	give := map[string]any{"expected_generation": 2, "public_fingerprint": made.Request.PublicFingerprint}
	e.clock.add(freshLife)
	if w := post(t, e, cookie, "/api/requests/delete", give); w.code != http.StatusPreconditionRequired {
		t.Fatalf("give up without a fresh code: %d %s", w.code, w.body)
	}
	if list := listWithRequests(t, e, cookie); list.Generation != 2 || len(list.Requests) != 1 {
		t.Fatalf("a refused give-up wrote: %+v", list)
	}
	fresh := apiCall(e.g, "POST", "/api/fresh", `{"code":"`+e.code(t)+`"}`, cookie, "https://"+localHost, true)
	if fresh.Code != http.StatusNoContent {
		t.Fatalf("fresh code: %d", fresh.Code)
	}
	cookie = sessionCookie(t, fresh)
	if w := post(t, e, cookie, "/api/requests/delete", give); w.code != http.StatusOK {
		t.Fatalf("give up: %d %s", w.code, w.body)
	}
	if list := listWithRequests(t, e, cookie); list.Generation != 3 || len(list.Requests) != 0 {
		t.Fatalf("after giving up: %+v", list)
	}
	if w := post(t, e, cookie, "/api/requests/delete", map[string]any{"expected_generation": 3, "public_fingerprint": made.Request.PublicFingerprint}); w.code != http.StatusNotFound {
		t.Fatalf("give up twice: %d %s", w.code, w.body)
	}
}

func TestLinuxRequestInputIsRefused(t *testing.T) {
	_, cookie, e := readyGate(t)
	codeStage := e.passwordStep(t, testPassword)
	good := `{"expected_generation":1,"algorithm":"ec-p256","dns_names":["shop.rootwell.invalid"]}`
	if w := apiCall(e.g, "POST", "/api/requests/create", good, nil, "https://"+localHost, true); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", w.Code)
	}
	if w := apiCall(e.g, "POST", "/api/requests/create", good, codeStage, "https://"+localHost, true); w.Code != http.StatusUnauthorized {
		t.Fatalf("a code-stage session: %d", w.Code)
	}
	if w := apiCall(e.g, "GET", "/api/requests/create", "", cookie, "", true); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", w.Code)
	}
	if w := apiCall(e.g, "POST", "/api/requests/create", good, cookie, "https://evil.invalid", true); w.Code != http.StatusForbidden {
		t.Fatalf("another site: %d", w.Code)
	}
	if w := apiCall(e.g, "POST", "/api/requests/create", good, cookie, "https://"+localHost, false); w.Code != http.StatusForbidden {
		t.Fatalf("without the page header: %d", w.Code)
	}
	for _, body := range []string{
		`{"expected_generation":1,"algorithm":"dsa-1024","dns_names":["shop.rootwell.invalid"]}`,
		`{"expected_generation":1,"algorithm":"ec-p256"}`,
		`{"expected_generation":1,"algorithm":"ec-p256","dns_names":["shop.rootwell.invalid"],"private_key":"AAAA"}`,
		`{"expected_generation":0,"algorithm":"ec-p256","dns_names":["shop.rootwell.invalid"]}`,
		`{"expected_generation":1,"algorithm":"ec-p256","dns_names":["not a name"]}`,
		`{"expected_generation":1,"algorithm":"ec-p256","dns_names":["10.0.0.1"]}`,
		`{"expected_generation":1,"algorithm":"ec-p256","renews":"not-a-fingerprint"}`,
	} {
		if w := apiCall(e.g, "POST", "/api/requests/create", body, cookie, "https://"+localHost, true); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	if w := apiCall(e.g, "POST", "/api/requests/create", `{"expected_generation":7,"algorithm":"ec-p256","dns_names":["shop.rootwell.invalid"]}`, cookie, "https://"+localHost, true); w.Code != http.StatusConflict {
		t.Fatalf("a stale page: %d", w.Code)
	}
	if list := listWithRequests(t, e, cookie); list.Generation != 1 || len(list.Requests) != 0 {
		t.Fatalf("a refused request wrote: %+v", list)
	}
}
