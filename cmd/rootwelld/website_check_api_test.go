package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/websitechain"
	"github.com/denyfirst/rootwell/internal/websiteprobe"
)

const websiteConsent = `{"target":"website.example.org","confirm":true}`

func TestWebsiteConsentExactAndNoSecrets(t *testing.T) {
	internal := `{"target":"10.0.0.5:8443","confirm":true}`
	for _, body := range []string{websiteConsent, internal, `{"confirm":true,"target":"https://website.example.org:443/"}`, `{"target":"website.example.org","confirm":null}`, `{"target":"website.example.org","confirm":false}`, `{"target":"website.example.org"}`, `{"Target":"website.example.org","confirm":true}`, websiteConsent + `{}`, `{"target":"website.example.org","confirm":true,"confirm":true}`, `{"target":"website.example.org","confirm":true,"password":"sentinel"}`, `{"target":"http://169.254.169.254","confirm":true}`, `{"target":null,"confirm":true}`, strings.Repeat(" ", 1025), "null", string([]byte{0xff})} {
		r := httptest.NewRequest("POST", "/api/website-check", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		target, ok := readWebsiteConsent(httptest.NewRecorder(), r)
		want := body == websiteConsent || body == internal || body == `{"confirm":true,"target":"https://website.example.org:443/"}`
		if ok != want || (ok && target != (websiteprobe.Target{Host: "website.example.org", Port: 443}) && target != (websiteprobe.Target{Host: "10.0.0.5", Port: 8443})) {
			t.Fatalf("unsafe consent: %q %+v %v", body, target, ok)
		}
	}
}

func TestWebsiteComparisonCannotUploadCertificatesOrTrustToAPI(t *testing.T) {
	for _, field := range []string{"certificate", "expected_certificate", "fingerprint", "private_key", "trust_bundle"} {
		body := `{"target":"website.example.org","confirm":true,"` + field + `":"private-input-sentinel"}`
		r := httptest.NewRequest("POST", "/api/website-check", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if _, ok := readWebsiteConsent(httptest.NewRecorder(), r); ok {
			t.Fatal("file/trust comparison input entered the server API")
		}
	}
}

func TestWebsiteGateNeedsReadyOriginConsentAndThrottleAndWritesNothing(t *testing.T) {
	g, cookie, e := readyGate(t)
	vaultFile := filepath.Join(e.dir, "rootwell.db")
	before, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	g.websiteCheck = func(ctx context.Context, target websiteprobe.Target, saved []*x509.Certificate, permit func() bool) (websitechain.Report, error) {
		calls++
		if !permit() || target != (websiteprobe.Target{Host: "website.example.org", Port: 443}) || len(saved) != 0 {
			t.Fatal("wrong authority")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > websiteprobe.Timeout+time.Second {
			t.Fatal("no total deadline")
		}
		return websitechain.Report{Schema: websitechain.Schema, State: "failed"}, nil
	}
	for _, bad := range []struct {
		method, body, origin string
		cookie               *http.Cookie
		header               bool
	}{
		{"POST", websiteConsent, "https://" + localHost, nil, true},
		{"GET", websiteConsent, "https://" + localHost, cookie, true},
		{"POST", websiteConsent, "http://evil.invalid", cookie, true},
		{"POST", websiteConsent, "https://" + localHost, cookie, false},
		{"POST", `{"target":"website.example.org","confirm":false}`, "https://" + localHost, cookie, true},
	} {
		w := apiCall(g, bad.method, "/api/website-check", bad.body, bad.cookie, bad.origin, bad.header)
		if w.Code < 400 || calls != 0 {
			t.Fatal("unauthorized network capability")
		}
	}
	for _, route := range []string{"/website-check", "/website-check.js"} {
		if w := call(g, "GET", route, "", nil); w.Code != 303 {
			t.Fatal("anonymous asset exposed")
		}
		if w := call(g, "GET", route, "", cookie); w.Code != 200 {
			t.Fatalf("ready asset missing %s: %d", route, w.Code)
		}
	}
	w := apiCall(g, "POST", "/api/website-check", websiteConsent, cookie, "https://"+localHost, true)
	if w.Code != 200 || calls != 1 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), `"state":"failed"`) {
		t.Fatal("diagnostic failure not preserved")
	}
	if w := apiCall(g, "POST", "/api/website-check", websiteConsent, cookie, "https://"+localHost, true); w.Code != 429 || calls != 1 {
		t.Fatal("repeat not bounded")
	}
	e.clock.add(websiteGap + time.Second)
	g.websiteBusy = true
	if w := apiCall(g, "POST", "/api/website-check", websiteConsent, cookie, "https://"+localHost, true); w.Code != 429 || calls != 1 {
		t.Fatal("concurrent check accepted")
	}
	g.websiteBusy = false
	g.websiteCheck = func(context.Context, websiteprobe.Target, []*x509.Certificate, func() bool) (websitechain.Report, error) {
		return websitechain.Report{}, &websiteprobe.Failure{Err: errors.New("private-sentinel"), Address: "10.0.0.9"}
	}
	w = apiCall(g, "POST", "/api/website-check", websiteConsent, cookie, "https://"+localHost, true)
	if w.Code != 502 || strings.Contains(w.Body.String(), "sentinel") || !strings.Contains(w.Body.String(), "did not finish") {
		t.Fatal("raw peer error reflected")
	}
	e.clock.add(websiteGap)
	g.websiteCheck = func(context.Context, websiteprobe.Target, []*x509.Certificate, func() bool) (websitechain.Report, error) {
		return websitechain.Report{}, &websiteprobe.Failure{Err: websiteprobe.ErrRefused, Address: "10.0.0.9"}
	}
	w = apiCall(g, "POST", "/api/website-check", websiteConsent, cookie, "https://"+localHost, true)
	if w.Code != 502 || !strings.Contains(w.Body.String(), "Nothing answers on port 443 at 10.0.0.9") {
		t.Fatalf("failure not explained: %s", w.Body.String())
	}
	after, err := os.ReadFile(vaultFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read-only check modified the vault")
	}
}

// The password alone, without the phone code, cannot use the website check,
// and a session that ended while a check ran never receives its result.
func TestWebsiteCodeStageAndLateSessionCannotPublish(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	g := e.g
	codeStage := e.passwordStep(t, testPassword)
	g.websiteCheck = func(context.Context, websiteprobe.Target, []*x509.Certificate, func() bool) (websitechain.Report, error) {
		t.Fatal("a code-stage session authorized network")
		return websitechain.Report{}, nil
	}
	if w := apiCall(g, "POST", "/api/website-check", websiteConsent, codeStage, "https://"+localHost, true); w.Code != http.StatusUnauthorized {
		t.Fatalf("code stage accepted: %d", w.Code)
	}
	cookie := e.signIn(t)
	g.websiteCheck = func(_ context.Context, _ websiteprobe.Target, _ []*x509.Certificate, permit func() bool) (websitechain.Report, error) {
		if !permit() {
			t.Fatal("initial permit refused")
		}
		call(g, "DELETE", "/api/session", "", cookie)
		if permit() {
			t.Fatal("revoked authority retained")
		}
		return websitechain.Report{Schema: websitechain.Schema, Hostname: "must-not-publish"}, nil
	}
	w := apiCall(g, "POST", "/api/website-check", websiteConsent, cookie, "https://"+localHost, true)
	if w.Code != 401 || strings.Contains(w.Body.String(), "must-not-publish") {
		t.Fatal("late result published")
	}
}

func FuzzWebsiteConsent(f *testing.F) {
	f.Add(websiteConsent)
	f.Add(`{"target":"https://127.0.0.1","confirm":true}`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 2048 {
			return
		}
		r := httptest.NewRequest("POST", "/api/website-check", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		target, ok := readWebsiteConsent(httptest.NewRecorder(), r)
		if ok {
			if again, err := websiteprobe.ParseTarget(target.String()); err != nil || again != target || strings.ContainsAny(target.Host, "/@?#[] ") {
				t.Fatal("unsafe destination admitted")
			}
		}
	})
}

func TestWebsiteFailuresAreExplainedWithoutPeerText(t *testing.T) {
	target := websiteprobe.Target{Host: "intranet.example.org", Port: 8443}
	for err, want := range map[error]string{
		websiteprobe.ErrBlocked:  "does not check its own machine",
		websiteprobe.ErrNotFound: "intranet.example.org was not found",
		websiteprobe.ErrDNS:      "did not answer for intranet.example.org",
		&websiteprobe.Failure{Err: websiteprobe.ErrRefused, Address: "10.1.2.3"}:   "Nothing answers on port 8443 at 10.1.2.3",
		&websiteprobe.Failure{Err: websiteprobe.ErrTimeout, Address: "10.1.2.3"}:   "10.1.2.3 did not answer on port 8443 in time",
		&websiteprobe.Failure{Err: websiteprobe.ErrNotTLS, Address: "10.1.2.3"}:    "not with HTTPS",
		&websiteprobe.Failure{Err: websiteprobe.ErrHandshake, Address: "10.1.2.3"}: "TLS 1.0 or 1.1",
		syscall.ECONNRESET:         "The check did not finish",
		errors.New("sentinel <b>"): "The check did not finish",
	} {
		if got := websiteFailure(target, err); !strings.Contains(got, want) || strings.Contains(got, "sentinel") || strings.Contains(got, "reset") {
			t.Fatalf("%v explained as %q", err, got)
		}
	}
}

// A check may end at a root the person saved in Certificates, and at nothing
// else: not an intermediate, not a website certificate.
func TestWebsiteCheckTrustsOnlyRootsSavedInCertificates(t *testing.T) {
	g, cookie, e := readyGate(t)
	now := time.Now()
	type cert struct {
		der []byte
		c   *x509.Certificate
		key ed25519.PrivateKey
	}
	serial := int64(0)
	mint := func(name string, ca bool, parent *cert) cert {
		serial++
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: ca}
		if ca {
			tmpl.KeyUsage = x509.KeyUsageCertSign
		} else {
			tmpl.DNSNames = []string{name}
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		signer, signerCert := key, tmpl
		if parent != nil {
			signer, signerCert = parent.key, parent.c
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert{der, c, key}
	}
	root := mint("Company Root", true, nil)
	issuer := mint("Company Issuing CA", true, &root)
	leaf := mint("intranet.example.org", false, &issuer)
	var files []byte
	for _, c := range []cert{leaf, issuer, root} {
		files = append(files, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})...)
	}
	records, err := certificatepair.Analyze(files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := ""
	for _, r := range records {
		if bytes.Equal(r.DER, leaf.der) {
			fingerprint = r.Fingerprint
		}
	}
	if _, _, err := g.certificates.Save(1, files, nil, nil, "", "", fingerprint, false, ""); err != nil {
		t.Fatal(err)
	}
	var got []*x509.Certificate
	g.websiteCheck = func(_ context.Context, _ websiteprobe.Target, saved []*x509.Certificate, _ func() bool) (websitechain.Report, error) {
		got = saved
		return websitechain.Report{Schema: websitechain.Schema, State: "verified"}, nil
	}
	e.clock.add(time.Minute)
	if w := apiCall(g, "POST", "/api/website-check", websiteConsent, cookie, "https://"+localHost, true); w.Code != 200 {
		t.Fatalf("check refused: %d %s", w.Code, w.Body.String())
	}
	if len(got) != 1 || !got[0].Equal(root.c) {
		t.Fatalf("saved roots: %d", len(got))
	}
}
