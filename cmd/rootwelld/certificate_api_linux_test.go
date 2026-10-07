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
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func TestLinuxCertificateLibraryCustodyDownloadAndFullRestore(t *testing.T) {
	g, path := testGate(t)
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	code, err := instanceaccess.EnrollRecovery(path, nextTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	backups := t.TempDir()
	if err := os.Chmod(backups, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := instanceaccess.InitializeInventory(path, filepath.Join(backups, "initial.rwfull"), nextTestPassword, code); err != nil {
		t.Fatal(err)
	}
	login := call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil)
	cookie := sessionCookie(t, login)
	pub, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("fixture generation failed")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "library.rootwell.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, pub, k)
	if err != nil {
		t.Fatal("fixture certificate failed")
	}
	private, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal("fixture key failed")
	}
	defer clear(private)
	record, canonical, err := certificatepair.Prepare(cert, private, nil, "", "Nginx")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"certificate": cert, "private_key": private, "expected_generation": 1, "location": "Nginx"}
	encode := func(input map[string]any) string {
		b, err := json.Marshal(input)
		if err != nil {
			t.Fatal("fixture request failed")
		}
		return string(b)
	}
	invoke := func(route string, input map[string]any) *httpResponse {
		w := inventoryCall(g, "POST", route, encode(input), cookie, "http://"+localHost, true)
		return &httpResponse{w.Code, w.Body.Bytes(), w.Header()}
	}
	// Check releases metadata but does not commit either object.
	checked := invoke("/api/certificates/check", request)
	if checked.code != 200 || !bytes.Contains(checked.body, []byte(`"has_private_key":true`)) {
		t.Fatal("pair preview failed")
	}
	before, err := os.ReadFile(filepath.Join(filepath.Dir(path), "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	listed := inventoryCall(g, "GET", "/api/inventory", "", cookie, "", true)
	if !bytes.Contains(listed.Body.Bytes(), []byte(`"records":[]`)) {
		t.Fatal("check wrote data")
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
		result := invoke("/api/certificates/save", bad)
		if result.code < 400 || bytes.Contains(result.body, []byte("secret-sentinel")) {
			t.Fatal("bad save accepted or reflected")
		}
		after, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "inventory.json"))
		if !bytes.Equal(before, after) {
			t.Fatal("refused save changed disk")
		}
	}
	if w := inventoryCall(g, "POST", "/api/certificates/save", encode(request), cookie, "http://evil.invalid", true); w.Code != 403 {
		t.Fatal("cross-origin save accepted")
	}
	if w := inventoryCall(g, "POST", "/api/certificates/save", encode(request), cookie, "http://"+localHost, false); w.Code != 403 {
		t.Fatal("headerless save accepted")
	}
	saved := invoke("/api/certificates/save", request)
	if saved.code != 201 || bytes.Contains(saved.body, []byte(base64.StdEncoding.EncodeToString(private))) {
		t.Fatal("pair save failed or leaked key")
	}
	for _, route := range []string{"/api/inventory", "/api/inventory/activity"} {
		w := inventoryCall(g, "GET", route, "", cookie, "", true)
		if w.Code != 200 || bytes.Contains(w.Body.Bytes(), private) || bytes.Contains(w.Body.Bytes(), []byte(base64.StdEncoding.EncodeToString(private))) {
			t.Fatal("listing/history leaked key or failed")
		}
	}
	image, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "inventory.json"))
	if bytes.Contains(image, private) || bytes.Contains(image, []byte(base64.StdEncoding.EncodeToString(private))) {
		t.Fatal("plaintext key on disk")
	}
	download := map[string]any{"fingerprint": record.Fingerprint, "expected_generation": 2, "pair": false}
	public := invoke("/api/certificates/download", download)
	if public.code != 200 || !bytes.Contains(public.body, []byte("BEGIN CERTIFICATE")) || bytes.Contains(public.body, []byte("PRIVATE KEY")) {
		t.Fatal("public download failed")
	}
	download["pair"] = true
	download["password"] = "wrong-password"
	download["output_password"] = []byte("new-download-password")
	if failed := invoke("/api/certificates/download", download); failed.code != 401 || bytes.Contains(failed.body, []byte("PRIVATE KEY")) {
		t.Fatal("private download skipped fresh authentication")
	}
	download["password"] = nextTestPassword
	for _, output := range [][]byte{[]byte("short"), []byte(nextTestPassword)} {
		download["output_password"] = output
		if failed := invoke("/api/certificates/download", download); failed.code != 400 || bytes.Contains(failed.body, []byte("PRIVATE KEY")) {
			t.Fatal("weak or reused output password accepted")
		}
	}
	download["output_password"] = []byte("new-download-password")
	pair := invoke("/api/certificates/download", download)
	if pair.code != 200 || pair.header.Get("Content-Type") != "application/zip" {
		t.Fatal("pair download failed")
	}
	archive, err := zip.NewReader(bytes.NewReader(pair.body), int64(len(pair.body)))
	if err != nil || len(archive.File) != 2 {
		t.Fatal("pair archive invalid")
	}
	var protected []byte
	for _, file := range archive.File {
		r, err := file.Open()
		if err != nil {
			t.Fatal("archive read failed")
		}
		data, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			t.Fatal("archive read failed")
		}
		if file.Name == "private-key.encrypted.pem" {
			protected = data
		}
	}
	if len(protected) == 0 || !bytes.Contains(protected, []byte("BEGIN ENCRYPTED PRIVATE KEY")) {
		t.Fatal("plaintext or absent key in pair export")
	}
	if pair.header.Get("Cache-Control") != "no-store" || bytes.Contains(pair.body, private) {
		t.Fatal("pair download cache or plaintext policy violated")
	}
	// Login plus four private export attempts exhaust the shared five/minute
	// budget; even the correct password must not bypass it.
	if refused := invoke("/api/certificates/download", download); refused.code != 429 {
		t.Fatal("private download ignored password attempt limit")
	}
	_, exportKey, err := certificatepair.Prepare(cert, protected, []byte("new-download-password"), "", "")
	if err != nil {
		t.Fatal("exported key does not round trip")
	}
	defer clear(exportKey)
	if result, err := keymatch.Match(cert, exportKey); err != nil || !result.Match {
		t.Fatal("export changed key identity")
	}
	// The same full snapshot/restore ceremony must preserve secret attachments.
	snapshot := filepath.Join(backups, "pair.rwfull")
	if err := instanceaccess.ExportFullSnapshot(path, snapshot, nextTestPassword, code); err != nil {
		t.Fatal("pair backup failed")
	}
	destination := t.TempDir()
	if err := os.Chmod(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	access := filepath.Join(destination, "access.json")
	if err := instanceaccess.RestoreFullSnapshot(snapshot, access, code, instanceaccess.SnapshotRecoveryCode); err != nil {
		t.Fatal("pair restore failed")
	}
	dataKey, id, err := instanceaccess.OpenWithIdentity(access, nextTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(dataKey)
	revision, err := instanceaccess.Revision(access)
	if err != nil {
		t.Fatal(err)
	}
	err = instanceaccess.WithCertificate(access, dataKey, id, revision, 2, record.Fingerprint, func(r publicinventory.Record, k []byte) error {
		if !r.HasPrivateKey || !bytes.Equal(k, private) {
			t.Fatal("restore lost pair")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := instanceaccess.ChangePassword(path, nextTestPassword, "replacement-password-for-test"); err != nil {
		t.Fatal(err)
	}
	if revoked := invoke("/api/certificates/download", download); revoked.code != 401 {
		t.Fatal("old session released key after access revision changed")
	}
}

type httpResponse struct {
	code   int
	body   []byte
	header http.Header
}
