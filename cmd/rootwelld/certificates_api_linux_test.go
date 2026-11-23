//go:build linux

package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/certstore"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/vault"
)

type httpResponse struct {
	code   int
	body   []byte
	header http.Header
}

type listed struct {
	Generation uint64 `json:"generation"`
	Records    []struct {
		Fingerprint   string   `json:"fingerprint"`
		Owner         string   `json:"owner"`
		Location      string   `json:"location"`
		Locations     []string `json:"locations"`
		HasPrivateKey bool     `json:"has_private_key"`
		KeyStatus     string   `json:"key_status"`
	} `json:"records"`
}

func listCertificates(t *testing.T, g *gate, cookie *http.Cookie) listed {
	t.Helper()
	w := apiCall(g, "GET", "/api/inventory", "", cookie, "", true)
	var out listed
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	return out
}

// selfSigned makes a leaf certificate and its PKCS #8 key.
func selfSigned(t *testing.T, name string) ([]byte, []byte) {
	t.Helper()
	pub, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, pub, k)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return cert, private
}

func TestLinuxCertificatesNeedAReadySessionAndThePageHeader(t *testing.T) {
	g, path := testGate(t)
	if w := apiCall(g, "GET", "/api/inventory", "", nil, "", true); w.Code != http.StatusUnauthorized {
		t.Fatal("anonymous list opened")
	}
	setup := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil))
	if w := apiCall(g, "GET", "/api/inventory", "", setup, "", true); w.Code != http.StatusForbidden {
		t.Fatal("setup session opened the list")
	}
	for route, body := range map[string]string{
		"/api/inventory/locations":        `{"fingerprint":"x","location":"server","expected_generation":1}`,
		"/api/inventory/owner":            `{"fingerprint":"x","owner":"team","expected_generation":1}`,
		"/api/inventory/locations/change": `{"fingerprint":"x","old_location":"server","action":"remove","expected_generation":1}`,
		"/api/inventory/delete":           `{"fingerprint":"x","typed_fingerprint":"x","confirmation":"delete-public-record","expected_generation":1}`,
	} {
		if w := apiCall(g, "POST", route, body, setup, "http://"+localHost, true); w.Code != http.StatusForbidden {
			t.Fatalf("setup session reached %s: %d", route, w.Code)
		}
	}
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	ready := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	if w := apiCall(g, "GET", "/api/inventory", "", ready, "", false); w.Code != http.StatusForbidden {
		t.Fatal("a list without the page header was answered")
	}
	cross := apiCall(g, "GET", "/api/inventory", "", ready, "", true)
	if cross.Code != http.StatusOK {
		t.Fatalf("ready list: %d", cross.Code)
	}
	if out := listCertificates(t, g, ready); out.Generation != 1 || len(out.Records) != 0 {
		t.Fatalf("a new vault's list: %+v", out)
	}
	if w := apiCall(g, "POST", "/api/inventory", `{"certificate":"AA=="}`, ready, "http://"+localHost, true); w.Code != http.StatusMethodNotAllowed {
		t.Fatal("the list accepted a write; certificates are added only through Save")
	}
}

func TestLinuxCertificatesLiveInTheVaultAndSurviveARestart(t *testing.T) {
	g, cookie, path := readyGate(t)
	cert, private := selfSigned(t, "library.rootwell.invalid")
	defer clear(private)
	record, canonical, err := certificatepair.Prepare(cert, private, nil, "", "Nginx")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(input map[string]any) string {
		b, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	invoke := func(route string, input map[string]any) *httpResponse {
		w := apiCall(g, "POST", route, encode(input), cookie, "http://"+localHost, true)
		return &httpResponse{w.Code, w.Body.Bytes(), w.Header()}
	}
	db := filepath.Join(filepath.Dir(path), "rootwell.db")
	request := map[string]any{"certificate": cert, "private_key": private, "expected_generation": 1, "location": "Nginx"}

	// Check shows the pair and writes nothing.
	if checked := invoke("/api/certificates/check", request); checked.code != 200 || !bytes.Contains(checked.body, []byte(`"has_private_key":true`)) {
		t.Fatalf("check: %d %s", checked.code, checked.body)
	}
	if out := listCertificates(t, g, cookie); out.Generation != 1 || len(out.Records) != 0 {
		t.Fatal("check wrote")
	}
	request["fingerprint"] = record.Fingerprint
	for _, mutation := range []func(map[string]any){
		func(m map[string]any) { m["private_key"] = []byte("secret-sentinel-malformed") },
		func(m map[string]any) { m["expected_generation"] = 2 },
		func(m map[string]any) { m["fingerprint"] = "00:00" },
	} {
		bad := map[string]any{}
		for key, value := range request {
			bad[key] = value
		}
		mutation(bad)
		if result := invoke("/api/certificates/save", bad); result.code < 400 || bytes.Contains(result.body, []byte("secret-sentinel")) {
			t.Fatal("a bad save was accepted or reflected")
		}
	}
	if out := listCertificates(t, g, cookie); out.Generation != 1 {
		t.Fatal("a refused save wrote")
	}
	if w := apiCall(g, "POST", "/api/certificates/save", encode(request), cookie, "http://evil.invalid", true); w.Code != 403 {
		t.Fatal("cross-origin save accepted")
	}
	if w := apiCall(g, "POST", "/api/certificates/save", encode(request), cookie, "http://"+localHost, false); w.Code != 403 {
		t.Fatal("headerless save accepted")
	}
	saved := invoke("/api/certificates/save", request)
	if saved.code != 201 || bytes.Contains(saved.body, []byte(base64.StdEncoding.EncodeToString(private))) {
		t.Fatalf("save: %d", saved.code)
	}
	if again := invoke("/api/certificates/save", map[string]any{"certificate": cert, "expected_generation": 2, "fingerprint": record.Fingerprint}); again.code != 409 ||
		again.header.Get("X-Rootwell-Refusal") != "duplicate-certificate" {
		t.Fatalf("a second copy: %d", again.code)
	}
	listing := apiCall(g, "GET", "/api/inventory", "", cookie, "", true)
	if bytes.Contains(listing.Body.Bytes(), []byte(base64.StdEncoding.EncodeToString(private))) {
		t.Fatal("the list carried the key")
	}
	if disk, err := os.ReadFile(db); err != nil || bytes.Contains(disk, private) || bytes.Contains(disk, []byte(base64.StdEncoding.EncodeToString(private))) ||
		bytes.Contains(disk, []byte("library.rootwell.invalid")) {
		t.Fatal("the key or the name is readable in the vault file")
	}

	// Places and owner, one generation at a time.
	if w := invoke("/api/inventory/locations", map[string]any{"fingerprint": record.Fingerprint, "location": "Mail", "expected_generation": 2}); w.code != 200 {
		t.Fatalf("add place: %d %s", w.code, w.body)
	}
	if w := invoke("/api/inventory/locations/change", map[string]any{"fingerprint": record.Fingerprint, "old_location": "Nginx", "new_location": "Web", "action": "rename", "expected_generation": 3}); w.code != 200 {
		t.Fatalf("rename place: %d %s", w.code, w.body)
	}
	if w := invoke("/api/inventory/owner", map[string]any{"fingerprint": record.Fingerprint, "owner": "Platform", "expected_generation": 4}); w.code != 200 {
		t.Fatalf("owner: %d %s", w.code, w.body)
	}
	if w := invoke("/api/inventory/owner", map[string]any{"fingerprint": record.Fingerprint, "owner": "Platform", "expected_generation": 5}); w.code != 409 || !strings.Contains(string(w.body), "unchanged") {
		t.Fatalf("an unchanged owner: %d %s", w.code, w.body)
	}
	if w := invoke("/api/inventory/owner", map[string]any{"fingerprint": record.Fingerprint, "owner": "Other", "expected_generation": 4}); w.code != 409 {
		t.Fatalf("an owner from an older page: %d", w.code)
	}

	// Downloads: the public file freely; the key only after the password.
	download := map[string]any{"fingerprint": record.Fingerprint, "expected_generation": 5, "pair": false}
	if public := invoke("/api/certificates/download", download); public.code != 200 || !bytes.Contains(public.body, []byte("BEGIN CERTIFICATE")) || bytes.Contains(public.body, []byte("PRIVATE KEY")) {
		t.Fatalf("public download: %d", public.code)
	}
	download["pair"] = true
	download["password"] = "wrong-password"
	download["output_password"] = []byte("new-download-password")
	if failed := invoke("/api/certificates/download", download); failed.code != 401 || bytes.Contains(failed.body, []byte("PRIVATE KEY")) {
		t.Fatal("the key left without the password")
	}
	download["password"] = nextTestPassword
	download["output_password"] = []byte(nextTestPassword)
	if failed := invoke("/api/certificates/download", download); failed.code != 400 {
		t.Fatal("the sign-in password was reused for the download")
	}
	download["output_password"] = []byte("new-download-password")
	pair := invoke("/api/certificates/download", download)
	if pair.code != 200 || pair.header.Get("Content-Type") != "application/zip" || pair.header.Get("Cache-Control") != "no-store" || bytes.Contains(pair.body, private) {
		t.Fatalf("pair download: %d", pair.code)
	}
	archive, err := zip.NewReader(bytes.NewReader(pair.body), int64(len(pair.body)))
	if err != nil {
		t.Fatal(err)
	}
	var protected []byte
	for _, file := range archive.File {
		if file.Name != "private-key.encrypted.pem" {
			continue
		}
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		protected, _ = io.ReadAll(r)
		_ = r.Close()
	}
	_, exported, err := certificatepair.Prepare(cert, protected, []byte("new-download-password"), "", "")
	if err != nil {
		t.Fatal("the downloaded key does not open with its own password")
	}
	defer clear(exported)
	if result, err := keymatch.Match(cert, exported); err != nil || !result.Match {
		t.Fatal("the download changed the key")
	}

	// A restart: the same vault, opened again with the same key, holds it all.
	g2, err := reopenGate(t, path)
	if err != nil {
		t.Fatal(err)
	}
	cookie2 := sessionCookie(t, call(g2, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	after := listCertificates(t, g2, cookie2)
	if after.Generation != 5 || len(after.Records) != 1 || after.Records[0].Owner != "Platform" ||
		strings.Join(after.Records[0].Locations, ",") != "Web,Mail" || !after.Records[0].HasPrivateKey || after.Records[0].KeyStatus != "matched" {
		t.Fatalf("after a restart: %+v", after)
	}

	// Delete needs the typed fingerprint and takes the key with it.
	if w := apiCall(g2, "POST", "/api/inventory/delete", encode(map[string]any{"fingerprint": record.Fingerprint, "typed_fingerprint": record.Fingerprint, "confirmation": "delete-public-record", "expected_generation": 5}), cookie2, "http://"+localHost, true); w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if out := listCertificates(t, g2, cookie2); out.Generation != 6 || len(out.Records) != 0 {
		t.Fatalf("after delete: %+v", out)
	}
}

func TestLinuxAKeyAddedLaterNeedsThePasswordAndIsNeverReplaced(t *testing.T) {
	g, cookie, _ := readyGate(t)
	cert, private := selfSigned(t, "later.rootwell.invalid")
	_, other := selfSigned(t, "other.rootwell.invalid")
	record, canonical, err := certificatepair.Prepare(cert, nil, nil, "", "")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	post := func(route string, input map[string]any) *httpResponse {
		b, _ := json.Marshal(input)
		w := apiCall(g, "POST", route, string(b), cookie, "http://"+localHost, true)
		return &httpResponse{w.Code, w.Body.Bytes(), w.Header()}
	}
	if w := post("/api/certificates/save", map[string]any{"certificate": cert, "expected_generation": 1, "fingerprint": record.Fingerprint}); w.code != 201 {
		t.Fatalf("save: %d %s", w.code, w.body)
	}
	if w := post("/api/certificates/key/check", map[string]any{"fingerprint": record.Fingerprint, "private_key": private, "expected_generation": 2}); w.code != 200 || !bytes.Contains(w.body, []byte(`"key_status":"matched"`)) {
		t.Fatalf("key check: %d %s", w.code, w.body)
	}
	if out := listCertificates(t, g, cookie); out.Generation != 2 || out.Records[0].HasPrivateKey {
		t.Fatal("the key check wrote")
	}
	if w := post("/api/certificates/key/save", map[string]any{"fingerprint": record.Fingerprint, "private_key": private, "expected_generation": 2, "password": "wrong-password"}); w.code != 401 {
		t.Fatalf("a key saved without the password: %d", w.code)
	}
	if w := post("/api/certificates/key/save", map[string]any{"fingerprint": record.Fingerprint, "private_key": private, "expected_generation": 2, "password": nextTestPassword}); w.code != 200 {
		t.Fatalf("key save: %d %s", w.code, w.body)
	}
	if w := post("/api/certificates/key/save", map[string]any{"fingerprint": record.Fingerprint, "private_key": other, "expected_generation": 3, "password": nextTestPassword, "allow_mismatch": true}); w.code != 409 ||
		w.header.Get("X-Rootwell-Refusal") != "key-already-attached" {
		t.Fatalf("a second key: %d", w.code)
	}
}

func TestLinuxAGateWithoutCustodySaysSoInsteadOfSaving(t *testing.T) {
	g, path := testGate(t)
	g.certificates = nil
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	if w := apiCall(g, "GET", "/api/inventory", "", cookie, "", true); w.Code != http.StatusNotImplemented {
		t.Fatalf("list without a vault: %d", w.Code)
	}
	if w := apiCall(g, "POST", "/api/certificates/save", `{"expected_generation":1}`, cookie, "http://"+localHost, true); w.Code != http.StatusNotImplemented {
		t.Fatalf("save without a vault: %d", w.Code)
	}
}

// reopenGate opens the test gate's vault again in a new gate, as a restart of
// rootwelld does. The first gate's vault is closed first: bbolt allows one
// writer process.
func reopenGate(t *testing.T, path string) (*gate, error) {
	t.Helper()
	key := testKeys[path]
	if closer, ok := testVaults[path]; ok {
		_ = closer.Close()
	}
	v, err := vault.Open(filepath.Dir(path), key)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = v.Close() })
	g, err := newGate(path, testWorkbenchAssets(t), localHost, certstore.New(v))
	if err == nil {
		t.Cleanup(func() { _ = g.Close() })
	}
	return g, err
}
