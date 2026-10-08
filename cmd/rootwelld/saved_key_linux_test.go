//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

func TestLinuxSavedKeyRequiresFreshAuthenticationAndPreservesRefusedImage(t *testing.T) {
	g, path := testGate(t)
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	code, err := instanceaccess.EnrollRecovery(path, nextTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	backups := t.TempDir()
	if err := os.Chmod(backups, 0700); err != nil {
		t.Fatal(err)
	}
	if err := instanceaccess.InitializeInventory(path, filepath.Join(backups, "initial.rwfull"), nextTestPassword, code); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("synthetic key generation failed")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "saved-key.rootwell.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal("synthetic certificate generation failed")
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("synthetic key encoding failed")
	}
	defer clear(private)
	_, wrong, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("synthetic key generation failed")
	}
	unrelated, err := x509.MarshalPKCS8PrivateKey(wrong)
	if err != nil {
		t.Fatal("synthetic key encoding failed")
	}
	defer clear(unrelated)
	record, canonical, err := certificatepair.Prepare(cert, nil, nil, "Team", "Nginx")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(input map[string]any) string {
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal("request encoding failed")
		}
		return string(body)
	}
	invoke := func(route string, input map[string]any) *httptest.ResponseRecorder {
		return inventoryCall(g, "POST", route, encode(input), cookie, "http://"+localHost, true)
	}
	if w := invoke("/api/certificates/save", map[string]any{"certificate": cert, "fingerprint": record.Fingerprint, "expected_generation": 1, "owner": "Team", "location": "Nginx"}); w.Code != http.StatusCreated {
		t.Fatal("public fixture save failed")
	}
	image := filepath.Join(filepath.Dir(path), "inventory.json")
	before, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := func() {
		t.Helper()
		after, err := os.ReadFile(image)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refused operation changed disk")
		}
	}
	input := map[string]any{"fingerprint": record.Fingerprint, "expected_generation": 2, "private_key": private}
	for _, route := range []string{"/api/certificates/key/check", "/api/certificates/key/save"} {
		input["password"] = nextTestPassword
		if route == "/api/certificates/key/check" {
			delete(input, "password")
		}
		if w := inventoryCall(g, "POST", route, encode(input), nil, "http://"+localHost, true); w.Code != 401 {
			t.Fatal("anonymous operation allowed")
		}
		if w := inventoryCall(g, "POST", route, encode(input), cookie, "http://evil.invalid", true); w.Code != 403 {
			t.Fatal("cross-origin operation allowed")
		}
		if w := inventoryCall(g, "POST", route, encode(input), cookie, "http://"+localHost, false); w.Code != 403 {
			t.Fatal("headerless operation allowed")
		}
		unchanged()
	}
	delete(input, "password")
	if w := invoke("/api/certificates/key/check", input); w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte(base64.StdEncoding.EncodeToString(private))) {
		t.Fatal("key check failed or leaked key")
	}
	unchanged()
	input["password"] = "secret-sentinel-wrong-password"
	if w := invoke("/api/certificates/key/save", input); w.Code != 401 || bytes.Contains(w.Body.Bytes(), []byte("secret-sentinel")) {
		t.Fatal("fresh authentication skipped or reflected")
	}
	unchanged()
	input["password"], input["private_key"] = nextTestPassword, unrelated
	if w := invoke("/api/certificates/key/save", input); w.Code != 400 {
		t.Fatal("unacknowledged unrelated key saved")
	}
	unchanged()
	input["private_key"] = private
	if w := invoke("/api/certificates/key/save", input); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"key_status":"matched"`)) || !bytes.Contains(w.Body.Bytes(), []byte(`"generation":3`)) || bytes.Contains(w.Body.Bytes(), []byte(base64.StdEncoding.EncodeToString(private))) {
		t.Fatal("valid direct attachment failed or leaked key")
	}
	before, err = os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	input["expected_generation"] = 3
	if w := invoke("/api/certificates/key/save", input); w.Code != 409 || w.Header().Get("X-Rootwell-Refusal") != "key-already-attached" {
		t.Fatal("existing key replaced")
	}
	unchanged()
	if w := invoke("/api/certificates/key/save", input); w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal("shared authentication budget bypassed")
	}
	unchanged()
	listed := inventoryCall(g, "GET", "/api/inventory", "", cookie, "", true)
	if listed.Code != 200 || !bytes.Contains(listed.Body.Bytes(), []byte(`"owner":"Team"`)) || !bytes.Contains(listed.Body.Bytes(), []byte("Nginx")) || bytes.Contains(listed.Body.Bytes(), []byte(base64.StdEncoding.EncodeToString(private))) {
		t.Fatal("notes lost or key leaked in listing")
	}
}
