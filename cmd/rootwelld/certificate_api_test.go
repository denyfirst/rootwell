package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// parseCertificateRequest runs the certificate request parser on body as if
// it were sent to route, and says whether it was accepted.
func parseCertificateRequest(t *testing.T, route, body string) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	r := httptest.NewRequest("POST", "http://"+localHost+route, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	input, ok := readCertificateInput(w, r)
	clear(input.Certificate)
	clear(input.PrivateKey)
	clear(input.KeyPassword)
	clear(input.OutputPassword)
	if strings.Contains(w.Body.String(), "secret-sentinel") {
		t.Fatalf("%s reflected a secret: %s", route, w.Body)
	}
	return w, ok
}

func TestKeyAttachmentRequestModesAreStrict(t *testing.T) {
	fp := strings.Repeat("AB:", 31) + "AB"
	check := `{"fingerprint":"` + fp + `","expected_generation":2,"private_key":"AQ==","key_password":""}`
	for _, route := range []string{"/api/certificates/key/check", "/api/certificates/key/save"} {
		valid := check
		if strings.HasSuffix(route, "save") {
			valid = strings.TrimSuffix(check, "}") + `,"allow_mismatch":false}`
		}
		parse := func(body string) bool {
			_, ok := parseCertificateRequest(t, route, body)
			return ok
		}
		if !parse(valid) {
			t.Fatal("valid attachment mode refused")
		}
		for _, extra := range []string{`,"certificate":"AQ=="`, `,"owner":"secret-sentinel"`, `,"location":"secret-sentinel"`, `,"primary_fingerprint":"` + fp + `"`, `,"pair":false`, `,"bundle":false`, `,"key_only":true`, `,"output_password":"AQ=="`, `,"private_key":"AQ=="`, `,"fingerprint":"` + fp + `"`, `,"password":"secret-sentinel"`} {
			if parse(strings.TrimSuffix(valid, "}") + extra + "}") {
				t.Fatalf("wrong-mode or duplicate attachment field accepted: %s", extra)
			}
		}
		for _, bad := range []string{strings.Replace(valid, `"private_key":"AQ=="`, `"private_key":""`, 1), strings.Replace(valid, `"private_key":"AQ=="`, `"private_key":null`, 1), strings.Replace(valid, `"expected_generation":2`, `"expected_generation":0`, 1), strings.Replace(valid, fp, "invalid", 1), valid + `{}`} {
			if parse(bad) {
				t.Fatal("malformed attachment accepted")
			}
		}
		if strings.HasSuffix(route, "check") {
			if parse(strings.TrimSuffix(check, "}") + `,"allow_mismatch":true}`) {
				t.Fatal("check accepted save authority")
			}
		} else if !parse(check) {
			// Attaching a key takes no password; the acknowledgement is optional.
			t.Fatal("a key save without allow_mismatch was refused")
		}
	}
}

func TestCertificateRequestModesRejectMalformedAndAmbiguousJSON(t *testing.T) {
	for _, body := range []string{
		`{"certificate":"AA==","expected_generation":1,"private_key":"AA==","private_key":"AA=="}`,
		`{"certificate":"AA==","expected_generation":1,"unknown":"secret-sentinel"}`,
		`{"certificate":"AA==","expected_generation":1} {}`,
		`{"certificate":"AA==","expected_generation":0}`,
		`{"certificate":"AA==","expected_generation":1,"password":"secret-sentinel"}`,
		`{"certificate":"AA==","expected_generation":1,"fingerprint":"x"}`,
		`{"certificate":"%%%","expected_generation":1}`,
		`{"certificate":[0],"expected_generation":1}`,
		`{"certificate":"AA==","private_key":null,"expected_generation":1}`,
		`{"certificate":"AA==","location":null,"expected_generation":1}`,
		`{"certificate":"AA==","expected_generation":1,"allow_mismatch":true}`,
		`{"certificate":"AA==","expected_generation":1,"primary_fingerprint":null}`,
		`{"certificate":"AA==","expected_generation":1,"primary_fingerprint":"bad"}`,
	} {
		if w, ok := parseCertificateRequest(t, "/api/certificates/check", body); ok || w.Code != http.StatusBadRequest {
			t.Fatal("ambiguous request accepted or reflected")
		}
	}
}

// The password that signs in is never part of a certificate request: a key
// download asks for a fresh phone code instead, and attaching a key asks for
// nothing more. A "password" field is an unknown field in every mode.
func TestCertificateRequestsRefuseAPasswordField(t *testing.T) {
	fp := strings.Repeat("AB:", 31) + "AB"
	output := base64.StdEncoding.EncodeToString([]byte("separate-key-password"))
	for route, valid := range map[string]string{
		"/api/certificates/check":     `{"certificate":"AA==","expected_generation":1}`,
		"/api/certificates/save":      `{"certificate":"AA==","expected_generation":1,"fingerprint":"` + fp + `"}`,
		"/api/certificates/key/check": `{"fingerprint":"` + fp + `","expected_generation":2,"private_key":"AQ=="}`,
		"/api/certificates/key/save":  `{"fingerprint":"` + fp + `","expected_generation":2,"private_key":"AQ==","allow_mismatch":false}`,
		"/api/certificates/download":  `{"fingerprint":"` + fp + `","expected_generation":1,"pair":true,"output_password":"` + output + `"}`,
	} {
		if _, ok := parseCertificateRequest(t, route, valid); !ok {
			t.Fatalf("%s: a valid request was refused", route)
		}
		for _, password := range []string{`"secret-sentinel"`, `""`, `null`} {
			body := strings.TrimSuffix(valid, "}") + `,"password":` + password + `}`
			if w, ok := parseCertificateRequest(t, route, body); ok || w.Code != http.StatusBadRequest {
				t.Fatalf("%s accepted a password field: %d", route, w.Code)
			}
		}
	}
}

// Every certificate endpoint and the page script answer only a signed-in
// session: anonymous and password-only (code stage) requests are refused.
func TestCertificateEndpointsNeedASignedInSession(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	codeStage := e.passwordStep(t, testPassword)
	for _, route := range []string{"/api/certificates/check", "/api/certificates/save", "/api/certificates/download", "/api/certificates/key/check", "/api/certificates/key/save", "/certificates.js"} {
		method, refused := "POST", http.StatusUnauthorized
		if route == "/certificates.js" {
			method, refused = "GET", http.StatusSeeOther
		}
		for _, cookie := range []*http.Cookie{nil, codeStage} {
			w := call(e.g, method, route, `{}`, cookie)
			if w.Code != refused || (route == "/certificates.js" && w.Header().Get("Location") != "/login") {
				t.Fatalf("%s opened without a signed-in session: %d", route, w.Code)
			}
		}
	}
}

func TestCertificateRequestBoundsAndDownloadMode(t *testing.T) {
	fp := strings.Repeat("AB:", 31) + "AB"
	for _, body := range []string{
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":true,"output_password":"` + base64.StdEncoding.EncodeToString([]byte("separate-key-password")) + `"}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false,"key_only":true,"output_password":"AA=="}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false,"bundle":true}`,
	} {
		w, ok := parseCertificateRequest(t, "/api/certificates/download", body)
		if !ok {
			t.Fatalf("valid download request refused: %d", w.Code)
		}
	}
	r := httptest.NewRequest("POST", "http://"+localHost+"/api/certificates/download", strings.NewReader(`{"fingerprint":"`+fp+`","expected_generation":1,"pair":false}`))
	r.Header.Set("Content-Type", "application/json")
	if input, ok := readCertificateInput(httptest.NewRecorder(), r); !ok || input.Fingerprint != fp || input.Expected != 1 {
		t.Fatal("a download request lost its fingerprint or generation")
	}
	for _, body := range []string{
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":null}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":true,"key_only":true,"output_password":"AA=="}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false,"key_only":true}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false,"key_only":null}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":true,"bundle":true,"output_password":"AA=="}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":true}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false,"output_password":"AA=="}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false,"password":"secret-sentinel"}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":true,"password":"secret-sentinel","output_password":"AA=="}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":true,"password":null,"output_password":"AA=="}`,
		`{"certificate":"AA==","expected_generation":1,"private_key":"` + base64.StdEncoding.EncodeToString(make([]byte, 64<<10+1)) + `"}`,
		strings.Repeat(" ", 240<<10+1),
		string([]byte{'{', 0xff, '}'}),
	} {
		if w, ok := parseCertificateRequest(t, "/api/certificates/download", body); ok || w.Code != http.StatusBadRequest {
			t.Fatal("invalid download request accepted or reflected")
		}
	}
}
