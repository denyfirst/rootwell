//go:build linux

package main

import (
	"archive/zip"
	"bytes"
	"crypto"
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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/youmark/pkcs8"
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

// post sends a page request with a JSON body to the env's current gate.
func post(t *testing.T, e *testEnv, cookie *http.Cookie, route string, input map[string]any) *httpResponse {
	t.Helper()
	b, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	w := apiCall(e.g, "POST", route, string(b), cookie, "https://"+localHost, true)
	return &httpResponse{w.Code, w.Body.Bytes(), w.Header()}
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
	e := newTestEnv(t).withAccount(t)
	g := e.g
	if w := apiCall(g, "GET", "/api/inventory", "", nil, "", true); w.Code != http.StatusUnauthorized {
		t.Fatal("anonymous list opened")
	}
	// The password alone, without the phone code, is not signed in.
	codeStage := e.passwordStep(t, testPassword)
	if w := apiCall(g, "GET", "/api/inventory", "", codeStage, "", true); w.Code != http.StatusUnauthorized {
		t.Fatalf("a code-stage session opened the list: %d", w.Code)
	}
	for route, body := range map[string]string{
		"/api/inventory/locations":        `{"fingerprint":"x","location":"server","expected_generation":1}`,
		"/api/inventory/owner":            `{"fingerprint":"x","owner":"team","expected_generation":1}`,
		"/api/inventory/locations/change": `{"fingerprint":"x","old_location":"server","action":"remove","expected_generation":1}`,
		"/api/inventory/delete":           `{"fingerprint":"x","typed_fingerprint":"x","confirmation":"delete-public-record","expected_generation":1}`,
	} {
		if w := apiCall(g, "POST", route, body, codeStage, "https://"+localHost, true); w.Code != http.StatusUnauthorized {
			t.Fatalf("a code-stage session reached %s: %d", route, w.Code)
		}
	}
	ready := e.signIn(t)
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
	if w := apiCall(g, "POST", "/api/inventory", `{"certificate":"AA=="}`, ready, "https://"+localHost, true); w.Code != http.StatusMethodNotAllowed {
		t.Fatal("the list accepted a write; certificates are added only through Save")
	}
}

func TestLinuxCertificatesLiveInTheVaultAndSurviveARestart(t *testing.T) {
	_, cookie, e := readyGate(t)
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
	invoke := func(route string, input map[string]any) *httpResponse { return post(t, e, cookie, route, input) }
	db := filepath.Join(e.dir, "rootwell.db")
	request := map[string]any{"certificate": cert, "private_key": private, "expected_generation": 1, "location": "Nginx"}

	// Check shows the pair and writes nothing.
	if checked := invoke("/api/certificates/check", request); checked.code != 200 || !bytes.Contains(checked.body, []byte(`"has_private_key":true`)) {
		t.Fatalf("check: %d %s", checked.code, checked.body)
	}
	if out := listCertificates(t, e.g, cookie); out.Generation != 1 || len(out.Records) != 0 {
		t.Fatal("check wrote")
	}
	request["fingerprint"] = record.Fingerprint
	for _, mutation := range []func(map[string]any){
		func(m map[string]any) { m["private_key"] = []byte("secret-sentinel-malformed") },
		func(m map[string]any) { m["expected_generation"] = 2 },
		func(m map[string]any) { m["fingerprint"] = "00:00" },
		func(m map[string]any) { m["password"] = testPassword },
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
	if out := listCertificates(t, e.g, cookie); out.Generation != 1 {
		t.Fatal("a refused save wrote")
	}
	if w := apiCall(e.g, "POST", "/api/certificates/save", encode(request), cookie, "http://evil.invalid", true); w.Code != 403 {
		t.Fatal("cross-origin save accepted")
	}
	if w := apiCall(e.g, "POST", "/api/certificates/save", encode(request), cookie, "https://"+localHost, false); w.Code != 403 {
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
	listing := apiCall(e.g, "GET", "/api/inventory", "", cookie, "", true)
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

	// Downloads: the public file freely; the key right after sign-in, or after
	// a fresh phone code.
	download := map[string]any{"fingerprint": record.Fingerprint, "expected_generation": 5, "pair": false}
	if public := invoke("/api/certificates/download", download); public.code != 200 || !bytes.Contains(public.body, []byte("BEGIN CERTIFICATE")) || bytes.Contains(public.body, []byte("PRIVATE KEY")) {
		t.Fatalf("public download: %d", public.code)
	}
	download["pair"] = true
	download["password"] = testPassword
	download["output_password"] = []byte("new-download-password")
	if failed := invoke("/api/certificates/download", download); failed.code != 400 || bytes.Contains(failed.body, []byte("PRIVATE KEY")) {
		t.Fatalf("a download with the sign-in password field: %d", failed.code)
	}
	delete(download, "password")
	for _, refused := range []string{"short-password", "a password with spaces in it"} {
		download["output_password"] = []byte(refused)
		if failed := invoke("/api/certificates/download", download); failed.code != 400 || bytes.Contains(failed.body, []byte("PRIVATE KEY")) {
			t.Fatalf("an output password the export refuses (%q): %d", refused, failed.code)
		}
	}
	download["output_password"] = []byte("new-download-password")
	pair := invoke("/api/certificates/download", download)
	if pair.code != 200 || pair.header.Get("Content-Type") != "application/zip" || pair.header.Get("Cache-Control") != "no-store" || bytes.Contains(pair.body, private) {
		t.Fatalf("pair download right after sign-in: %d %s", pair.code, pair.body)
	}
	openPair(t, cert, pair.body)

	// Ten minutes on, the key needs a fresh phone code; the public file never does.
	e.clock.add(freshLife)
	for _, secret := range []map[string]any{
		{"fingerprint": record.Fingerprint, "expected_generation": 5, "pair": true, "output_password": []byte("new-download-password")},
		{"fingerprint": record.Fingerprint, "expected_generation": 5, "pair": false, "key_only": true, "output_password": []byte("new-download-password")},
	} {
		if late := invoke("/api/certificates/download", secret); late.code != http.StatusPreconditionRequired || bytes.Contains(late.body, []byte("PRIVATE KEY")) {
			t.Fatalf("a key download without a fresh code: %d", late.code)
		}
	}
	for _, public := range []map[string]any{
		{"fingerprint": record.Fingerprint, "expected_generation": 5, "pair": false},
		{"fingerprint": record.Fingerprint, "expected_generation": 5, "pair": false, "bundle": true},
	} {
		if w := invoke("/api/certificates/download", public); w.code != 200 || !bytes.Contains(w.body, []byte("BEGIN CERTIFICATE")) {
			t.Fatalf("a public download asked for a fresh code: %d", w.code)
		}
	}
	fresh := apiCall(e.g, "POST", "/api/fresh", `{"code":"`+e.code(t)+`"}`, cookie, "https://"+localHost, true)
	if fresh.Code != http.StatusNoContent {
		t.Fatalf("fresh code: %d %s", fresh.Code, fresh.Body)
	}
	// A fresh code moves the session to a new token.
	cookie = sessionCookie(t, fresh)
	if keyOnly := invoke("/api/certificates/download", map[string]any{"fingerprint": record.Fingerprint, "expected_generation": 5, "pair": false, "key_only": true, "output_password": []byte("new-download-password")}); keyOnly.code != 200 ||
		!bytes.Contains(keyOnly.body, []byte("ENCRYPTED PRIVATE KEY")) {
		t.Fatalf("a key download after a fresh code: %d %s", keyOnly.code, keyOnly.body)
	}
	pair = invoke("/api/certificates/download", download)
	if pair.code != 200 || pair.header.Get("Content-Type") != "application/zip" {
		t.Fatalf("pair download after a fresh code: %d %s", pair.code, pair.body)
	}
	openPair(t, cert, pair.body)

	// A restart: the same vault, opened again with the same key, holds it all.
	e.reopen(t)
	cookie = e.signIn(t)
	after := listCertificates(t, e.g, cookie)
	if after.Generation != 5 || len(after.Records) != 1 || after.Records[0].Owner != "Platform" ||
		strings.Join(after.Records[0].Locations, ",") != "Web,Mail" || !after.Records[0].HasPrivateKey || after.Records[0].KeyStatus != "matched" {
		t.Fatalf("after a restart: %+v", after)
	}

	// Delete needs the typed fingerprint and takes the key with it; with a key
	// saved, it needs a fresh phone code too.
	remove := map[string]any{"fingerprint": record.Fingerprint, "typed_fingerprint": record.Fingerprint, "confirmation": "delete-public-record", "expected_generation": 5}
	e.clock.add(freshLife)
	if w := invoke("/api/inventory/delete", remove); w.code != http.StatusPreconditionRequired {
		t.Fatalf("delete with a key, without a fresh code: %d %s", w.code, w.body)
	}
	if out := listCertificates(t, e.g, cookie); out.Generation != 5 || len(out.Records) != 1 || !out.Records[0].HasPrivateKey {
		t.Fatalf("a refused delete wrote: %+v", out)
	}
	fresh = apiCall(e.g, "POST", "/api/fresh", `{"code":"`+e.code(t)+`"}`, cookie, "https://"+localHost, true)
	if fresh.Code != http.StatusNoContent {
		t.Fatalf("fresh code: %d", fresh.Code)
	}
	cookie = sessionCookie(t, fresh)
	if w := invoke("/api/inventory/delete", remove); w.code != 200 {
		t.Fatalf("delete: %d %s", w.code, w.body)
	}
	if out := listCertificates(t, e.g, cookie); out.Generation != 6 || len(out.Records) != 0 {
		t.Fatalf("after delete: %+v", out)
	}
}

// openPair checks a pair download: its key opens with the download password
// alone and is the certificate's own key.
func openPair(t *testing.T, cert, archiveBytes []byte) {
	t.Helper()
	archive, err := zip.NewReader(bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
	if err != nil {
		t.Fatal(err)
	}
	var protected []byte
	files := map[string][]byte{}
	var names []string
	for _, file := range archive.File {
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		files[file.Name], _ = io.ReadAll(r)
		_ = r.Close()
		names = append(names, file.Name)
	}
	// The names servers expect, the full chain led by the certificate, and a
	// key that is locked.
	protected = files["privkey.pem"]
	if want := []string{"fullchain.pem", "cert.pem", "privkey.pem", "HOW-TO-INSTALL.txt"}; !slices.Equal(names, want) && !slices.Equal(names, []string{"fullchain.pem", "cert.pem", "chain.pem", "privkey.pem", "HOW-TO-INSTALL.txt"}) {
		t.Fatalf("zip holds %v", names)
	}
	// The notes say how nginx and Apache read a locked key, and hold no secret.
	if notes := string(files["HOW-TO-INSTALL.txt"]); !strings.Contains(notes, "ssl_password_file") || !strings.Contains(notes, "SSLCertificateKeyFile") || strings.Contains(notes, "new-download-password") {
		t.Fatalf("the install notes read: %s", notes)
	}
	if !bytes.HasPrefix(files["fullchain.pem"], files["cert.pem"]) || !bytes.Equal(files["fullchain.pem"], append(bytes.Clone(files["cert.pem"]), files["chain.pem"]...)) ||
		!bytes.Contains(protected, []byte("BEGIN ENCRYPTED PRIVATE KEY")) || bytes.Contains(protected, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("the zip's files are not the certificate, its chain and a locked key")
	}
	_, exported, err := certificatepair.Prepare(cert, protected, []byte("new-download-password"), "", "")
	if err != nil {
		t.Fatal("the downloaded key does not open with its own password")
	}
	defer clear(exported)
	if result, err := keymatch.Match(cert, exported); err != nil || !result.Match {
		t.Fatal("the download changed the key")
	}
}

func TestLinuxAKeyAddedLaterIsCheckedAndNeverReplaced(t *testing.T) {
	_, cookie, e := readyGate(t)
	cert, private := selfSigned(t, "later.rootwell.invalid")
	_, other := selfSigned(t, "other.rootwell.invalid")
	record, canonical, err := certificatepair.Prepare(cert, nil, nil, "", "")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if w := post(t, e, cookie, "/api/certificates/save", map[string]any{"certificate": cert, "expected_generation": 1, "fingerprint": record.Fingerprint}); w.code != 201 {
		t.Fatalf("save: %d %s", w.code, w.body)
	}
	if w := post(t, e, cookie, "/api/certificates/key/check", map[string]any{"fingerprint": record.Fingerprint, "private_key": private, "expected_generation": 2}); w.code != 200 || !bytes.Contains(w.body, []byte(`"key_status":"matched"`)) {
		t.Fatalf("key check: %d %s", w.code, w.body)
	}
	if out := listCertificates(t, e.g, cookie); out.Generation != 2 || out.Records[0].HasPrivateKey {
		t.Fatal("the key check wrote")
	}
	// The sign-in password is no part of attaching a key.
	if w := post(t, e, cookie, "/api/certificates/key/save", map[string]any{"fingerprint": record.Fingerprint, "private_key": private, "expected_generation": 2, "password": testPassword}); w.code != 400 {
		t.Fatalf("a key save with a password field: %d", w.code)
	}
	if w := post(t, e, cookie, "/api/certificates/key/save", map[string]any{"fingerprint": record.Fingerprint, "private_key": other, "expected_generation": 2}); w.code < 400 {
		t.Fatalf("a key that does not match was saved without the acknowledgement: %d", w.code)
	}
	if out := listCertificates(t, e.g, cookie); out.Generation != 2 || out.Records[0].HasPrivateKey {
		t.Fatal("a refused key save wrote")
	}
	if w := post(t, e, cookie, "/api/certificates/key/save", map[string]any{"fingerprint": record.Fingerprint, "private_key": private, "expected_generation": 2}); w.code != 200 {
		t.Fatalf("key save: %d %s", w.code, w.body)
	}
	if out := listCertificates(t, e.g, cookie); out.Generation != 3 || !out.Records[0].HasPrivateKey || out.Records[0].KeyStatus != "matched" {
		t.Fatalf("after the key save: %+v", out)
	}
	if w := post(t, e, cookie, "/api/certificates/key/save", map[string]any{"fingerprint": record.Fingerprint, "private_key": other, "expected_generation": 3, "allow_mismatch": true}); w.code != 409 ||
		w.header.Get("X-Rootwell-Refusal") != "key-already-attached" {
		t.Fatalf("a second key: %d", w.code)
	}
}

// A key password that does not open the key is named as wrong, apart from a
// key that still needs one, on both the Add check and a key added later.
func TestLinuxAWrongKeyPasswordIsNamed(t *testing.T) {
	_, cookie, e := readyGate(t)
	cert, private := selfSigned(t, "locked.rootwell.invalid")
	key, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := pkcs8.MarshalPrivateKey(key, []byte("synthetic-key-password-2026"), &pkcs8.Opts{Cipher: pkcs8.AES256CBC,
		KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 2048, HMACHash: crypto.SHA256}})
	if err != nil {
		t.Fatal(err)
	}
	check := map[string]any{"certificate": cert, "private_key": locked, "expected_generation": 1}
	if w := post(t, e, cookie, "/api/certificates/check", check); w.code != 422 || w.header.Get("X-Rootwell-Refusal") != "" {
		t.Fatalf("no password: %d %q", w.code, w.header.Get("X-Rootwell-Refusal"))
	}
	check["key_password"] = []byte("not-the-password")
	if w := post(t, e, cookie, "/api/certificates/check", check); w.code != 422 || w.header.Get("X-Rootwell-Refusal") != "key-password-wrong" || !bytes.Contains(w.body, []byte("does not open the key")) {
		t.Fatalf("wrong password: %d %q %s", w.code, w.header.Get("X-Rootwell-Refusal"), w.body)
	}
	check["key_password"] = []byte("synthetic-key-password-2026")
	if w := post(t, e, cookie, "/api/certificates/check", check); w.code != 200 || !bytes.Contains(w.body, []byte(`"key_status":"matched"`)) {
		t.Fatalf("right password: %d %s", w.code, w.body)
	}
	record, canonical, err := certificatepair.Prepare(cert, nil, nil, "", "")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if w := post(t, e, cookie, "/api/certificates/save", map[string]any{"certificate": cert, "expected_generation": 1, "fingerprint": record.Fingerprint}); w.code != 201 {
		t.Fatalf("save: %d %s", w.code, w.body)
	}
	later := map[string]any{"fingerprint": record.Fingerprint, "private_key": locked, "key_password": []byte("not-the-password"), "expected_generation": 2}
	if w := post(t, e, cookie, "/api/certificates/key/check", later); w.code != 422 || w.header.Get("X-Rootwell-Refusal") != "key-password-wrong" {
		t.Fatalf("wrong password for a key added later: %d %q", w.code, w.header.Get("X-Rootwell-Refusal"))
	}
}

// Only a saved key makes a delete ask for a fresh phone code.
func TestLinuxACertificateWithoutAKeyIsDeletedWithoutAFreshCode(t *testing.T) {
	_, cookie, e := readyGate(t)
	cert, _ := selfSigned(t, "public.rootwell.invalid")
	record, canonical, err := certificatepair.Prepare(cert, nil, nil, "", "")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if w := post(t, e, cookie, "/api/certificates/save", map[string]any{"certificate": cert, "expected_generation": 1, "fingerprint": record.Fingerprint}); w.code != 201 {
		t.Fatalf("save: %d %s", w.code, w.body)
	}
	e.clock.add(freshLife)
	if got := status(t, e.g, cookie); got == nil || got["fresh"] != false {
		t.Fatalf("the session should be signed in and not fresh: %v", got)
	}
	if w := post(t, e, cookie, "/api/inventory/delete", map[string]any{"fingerprint": record.Fingerprint, "typed_fingerprint": record.Fingerprint, "confirmation": "delete-public-record", "expected_generation": 2}); w.code != 200 {
		t.Fatalf("delete without a key: %d %s", w.code, w.body)
	}
	if out := listCertificates(t, e.g, cookie); out.Generation != 3 || len(out.Records) != 0 {
		t.Fatalf("after delete: %+v", out)
	}
}
