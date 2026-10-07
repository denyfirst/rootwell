package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
		r := httptest.NewRequest("POST", "http://"+localHost+"/api/certificates/check", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		_, ok := readCertificateInput(w, r)
		if ok || w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("ambiguous request accepted or reflected")
		}
	}
	for _, route := range []string{"/api/certificates/check", "/api/certificates/save", "/api/certificates/download"} {
		g, _ := testGate(t)
		w := call(g, "POST", route, `{}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatal("anonymous custody endpoint opened")
		}
		setup := call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil)
		cookie := sessionCookie(t, setup)
		if w := call(g, "POST", route, `{}`, cookie); w.Code != http.StatusForbidden {
			t.Fatal("setup custody endpoint opened")
		}
	}
}

func TestCertificateRequestBoundsAndDownloadMode(t *testing.T) {
	fp := strings.Repeat("AB:", 31) + "AB"
	for _, body := range []string{
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":true,"password":"instance-password","output_password":"` + base64.StdEncoding.EncodeToString([]byte("separate-key-password")) + `"}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false,"key_only":true,"password":"instance-password","output_password":"AA=="}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false,"bundle":true}`,
	} {
		r := httptest.NewRequest("POST", "http://"+localHost+"/api/certificates/download", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		input, ok := readCertificateInput(w, r)
		if !ok || input.Fingerprint != fp || input.Expected != 1 {
			t.Fatal("valid download request refused")
		}
		clear(input.OutputPassword)
	}
	for _, body := range []string{
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":null}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":true,"key_only":true,"password":"instance-password","output_password":"AA=="}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false,"key_only":true}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false,"key_only":null}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":true,"bundle":true,"password":"instance-password","output_password":"AA=="}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":false,"password":"secret-sentinel"}`,
		`{"fingerprint":"` + fp + `","expected_generation":1,"pair":true,"password":null,"output_password":"AA=="}`,
		`{"certificate":"AA==","expected_generation":1,"private_key":"` + base64.StdEncoding.EncodeToString(make([]byte, 64<<10+1)) + `"}`,
		strings.Repeat(" ", 240<<10+1),
		string([]byte{'{', 0xff, '}'}),
	} {
		r := httptest.NewRequest("POST", "http://"+localHost+"/api/certificates/download", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		if _, ok := readCertificateInput(w, r); ok || w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("invalid download request accepted or reflected")
		}
	}
}
