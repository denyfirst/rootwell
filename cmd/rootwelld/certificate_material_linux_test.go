//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/browserprivateconvert"
	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/keymatch"
)

func TestLinuxMaterialMismatchExportAndBundleFullRestore(t *testing.T) {
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
	login := call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil)
	cookie := sessionCookie(t, login)
	pub, k, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "material.rootwell.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, pub, k)
	if err != nil {
		t.Fatal("fixture certificate failed")
	}
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	private, err := x509.MarshalPKCS8PrivateKey(wrong)
	if err != nil {
		t.Fatal("fixture key failed")
	}
	defer clear(private)
	invoke := func(route string, input map[string]any) *httpResponse {
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal("fixture encoding failed")
		}
		w := inventoryCall(g, "POST", route, string(body), cookie, "http://"+localHost, true)
		return &httpResponse{w.Code, w.Body.Bytes(), w.Header()}
	}
	request := map[string]any{"certificate": cert, "private_key": private, "expected_generation": 1}
	checked := invoke("/api/certificates/check", request)
	if checked.code != 200 || !bytes.Contains(checked.body, []byte(`"key_status":"mismatch"`)) {
		t.Fatal("mismatch preview refused or mislabeled")
	}
	r, canonical, err := certificatepair.PrepareBundle(cert, private, nil, "", "", "")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	request["fingerprint"] = r.Fingerprint
	before, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "inventory.json"))
	if result := invoke("/api/certificates/save", request); result.code != 400 {
		t.Fatal("unacknowledged mismatch saved")
	}
	after, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "inventory.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("refusal changed disk")
	}
	request["allow_mismatch"] = true
	if result := invoke("/api/certificates/save", request); result.code != 201 || !bytes.Contains(result.body, []byte(`"key_status":"mismatch"`)) {
		t.Fatal("explicit loose attachment refused")
	}
	download := map[string]any{"fingerprint": r.Fingerprint, "expected_generation": 2, "pair": true, "password": nextTestPassword, "output_password": []byte("new-output-password-2026")}
	if result := invoke("/api/certificates/download", download); result.code != 400 || bytes.Contains(result.body, []byte("BEGIN")) {
		t.Fatal("mismatch used for pair output")
	}
	download["pair"] = false
	download["key_only"] = true
	download["password"] = "wrong-password"
	if result := invoke("/api/certificates/download", download); result.code != 401 {
		t.Fatal("key-only export skipped fresh authentication")
	}
	download["password"] = nextTestPassword
	result := invoke("/api/certificates/download", download)
	if result.code != 200 || result.header.Get("Content-Type") != "application/x-pem-file" || !bytes.Contains(result.body, []byte("BEGIN ENCRYPTED PRIVATE KEY")) || bytes.Contains(result.body, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("separate encrypted key export failed")
	}
	err = browserprivateconvert.WithInputKey(result.body, []byte("new-output-password-2026"), func(k any, _ keymatch.Encoding) error {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		defer clear(der)
		if err != nil || !bytes.Equal(der, private) {
			t.Fatal("loose export changed key")
		}
		return nil
	})
	if err != nil {
		t.Fatal("key-only output cannot decrypt")
	}
	// A second record stores an unordered leaf + CA bundle atomically.
	rp, rk, _ := ed25519.GenerateKey(rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "material synthetic issuer"}, NotBefore: template.NotBefore, NotAfter: template.NotAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, err := x509.CreateCertificate(rand.Reader, rt, rt, rp, rk)
	if err != nil {
		t.Fatal("fixture root failed")
	}
	template.SerialNumber = big.NewInt(2)
	leaf, err := x509.CreateCertificate(rand.Reader, template, rt, pub, rk)
	if err != nil {
		t.Fatal("fixture signed leaf failed")
	}
	matching, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal("fixture key marshal failed")
	}
	defer clear(matching)
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})...)
	r, canonical, err = certificatepair.PrepareBundle(bundle, matching, nil, "", "", "")
	clear(canonical)
	if err != nil {
		t.Fatal(err)
	}
	request = map[string]any{"certificate": bundle, "expected_generation": 2, "fingerprint": r.Fingerprint}
	if saved := invoke("/api/certificates/save", request); saved.code != 201 || !bytes.Contains(saved.body, []byte(`"bundle_count":2`)) {
		t.Fatal("bundle pair save failed")
	}
	attachment := map[string]any{"fingerprint": r.Fingerprint, "expected_generation": 3, "private_key": matching}
	if checked := invoke("/api/certificates/key/check", attachment); checked.code != 200 || !bytes.Contains(checked.body, []byte(`"key_status":"matched"`)) {
		t.Fatal("saved public bundle key check failed")
	}
	attachment["password"] = nextTestPassword
	if saved := invoke("/api/certificates/key/save", attachment); saved.code != 200 || !bytes.Contains(saved.body, []byte(`"bundle_count":2`)) {
		t.Fatal("saved public bundle key attachment failed")
	}
	delete(attachment, "password")
	attachment["expected_generation"] = 4
	if existing := invoke("/api/certificates/key/check", attachment); existing.code != 409 || existing.header.Get("X-Rootwell-Refusal") != "key-already-attached" {
		t.Fatal("attached key still presented as addable")
	}
	public := invoke("/api/certificates/download", map[string]any{"fingerprint": r.Fingerprint, "expected_generation": 4, "pair": false, "bundle": true})
	if public.code != 200 || bytes.Count(public.body, []byte("BEGIN CERTIFICATE")) != 2 || bytes.Contains(public.body, []byte("PRIVATE KEY")) {
		t.Fatal("bundle public export lost material or leaked key")
	}
	snapshot := filepath.Join(backups, "complete.rwfull")
	if err := instanceaccess.ExportFullSnapshot(path, snapshot, nextTestPassword, code); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(t.TempDir(), "restored")
	if err := os.Mkdir(fresh, 0700); err != nil {
		t.Fatal(err)
	}
	freshPath := filepath.Join(fresh, "access.json")
	if err := instanceaccess.RestoreFullSnapshot(snapshot, freshPath, code, instanceaccess.SnapshotRecoveryCode); err != nil {
		t.Fatal(err)
	}
	dataKey, id, err := instanceaccess.OpenWithIdentity(freshPath, nextTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(dataKey)
	revision, err := instanceaccess.Revision(freshPath)
	if err != nil {
		t.Fatal(err)
	}
	records, gen, err := instanceaccess.ReadInventory(freshPath, dataKey, id, revision)
	if err != nil || gen != 4 || len(records) != 2 || records[0].KeyStatus != "mismatch" || records[1].KeyStatus != "matched" || len(records[1].BundleDER) != 2 {
		t.Fatal("full restore changed status or lost bundle/key")
	}
}
