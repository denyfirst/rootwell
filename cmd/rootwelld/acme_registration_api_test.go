package main

import (
	"encoding/base64"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

const registrationPreviewInput = `{"provider":"letsencrypt-staging","confirm":true,"expected_generation":2}`
const registrationReconcileInput = `{"provider":"letsencrypt-staging","confirm":true,"expected_generation":3,"password":"` + nextTestPassword + `"}`

func registrationRequest(preview string) string {
	return `{"provider":"letsencrypt-staging","confirm":true,"expected_generation":2,"password":"` + nextTestPassword + `","preview":"` + preview + `","terms_agreed":true}`
}

func TestRegistrationRequestStrictShapesRefuseAuthorityAndPartialSecrets(t *testing.T) {
	register := registrationRequest(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	for mode, valid := range map[string]string{"preview": registrationPreviewInput, "register": register, "reconcile": registrationReconcileInput} {
		parse := func(body string, want bool) {
			t.Helper()
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			input, ok := readRegistrationInput(httptest.NewRecorder(), r, mode)
			if ok != want || !ok && (input.password != "" || input.expected != 0 || input.preview != "") {
				t.Fatal("registration parser returned unsafe/partial input")
			}
		}
		parse(valid, true)
		for _, bad := range []string{"null", "[]", valid + "{}", string([]byte{0xff}), strings.Repeat(" ", 4097), strings.Replace(valid, `"confirm":true`, `"confirm":false`, 1), strings.Replace(valid, `"confirm":true`, `"confirm":null`, 1), strings.Replace(valid, `"expected_generation":`, `"Expected_generation":`, 1), strings.Replace(strings.Replace(valid, `"expected_generation":2`, `"expected_generation":null`, 1), `"expected_generation":3`, `"expected_generation":null`, 1), strings.Replace(valid, `"provider":"letsencrypt-staging"`, `"provider":"production"`, 1)} {
			parse(bad, false)
		}
		for _, extra := range []string{`"confirm":true`, `"account_url":"http://127.0.0.1"`, `"terms_url":"https://evil.invalid"`, `"private_key":"secret-sentinel"`, `"domains":["example.com"]`, `"contact":["mailto:x@example.com"]`, `"externalAccountBinding":{}`} {
			parse(strings.TrimSuffix(valid, "}")+","+extra+"}", false)
		}
		if mode == "register" {
			for _, bad := range []string{strings.Replace(valid, `"terms_agreed":true`, `"terms_agreed":false`, 1), strings.Replace(valid, `"password":"`+nextTestPassword+`"`, `"password":null`, 1), strings.Replace(valid, `"preview":"`, `"Preview":"`, 1)} {
				parse(bad, false)
			}
		}
	}
}

func TestRegistrationGateRequiresReadyOriginMetadataAndNativeRefusal(t *testing.T) {
	g, path := testGate(t)
	setup := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+initialTestPassword+`"}`, nil))
	for _, route := range []string{"/api/acme/registration/preview", "/api/acme/registration/register", "/api/acme/registration/reconcile", "/acme-registration.js"} {
		if strings.HasPrefix(route, "/api/") {
			if w := accountCall(g, "POST", route, registrationPreviewInput, setup, "http://"+localHost, true); w.Code != 403 {
				t.Fatal("setup granted registration authority")
			}
		}
		if w := call(g, "GET", route, "", nil); strings.HasSuffix(route, ".js") && w.Code != 303 {
			t.Fatal("anonymous registration asset exposed")
		}
	}
	if err := instanceaccess.ChangeInitialPassword(path, initialTestPassword, nextTestPassword); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	for _, bad := range []struct {
		method, route, origin string
		header                bool
	}{{"GET", "/api/acme/registration/preview", "http://" + localHost, true}, {"POST", "/api/acme/registration/preview?password=secret-sentinel", "http://" + localHost, true}, {"POST", "/api/acme/registration/preview", "http://evil.invalid", true}, {"POST", "/api/acme/registration/preview", "http://" + localHost, false}} {
		w := accountCall(g, bad.method, bad.route, registrationPreviewInput, cookie, bad.origin, bad.header)
		if w.Code == 200 || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("unsafe registration route accepted/reflected")
		}
	}
	if runtime.GOOS != "linux" {
		if w := accountCall(g, "POST", "/api/acme/registration/preview", registrationPreviewInput, cookie, "http://"+localHost, true); w.Code != 503 {
			t.Fatal("native registration accepted")
		}
	}
	if w := call(g, "GET", "/acme-registration.js", "", cookie); w.Code != 200 || len(w.Body.Bytes()) == 0 {
		t.Fatal("ready registration asset unavailable")
	}
}

func FuzzStagingRegistrationRequest(f *testing.F) {
	f.Add([]byte(registrationPreviewInput))
	f.Add([]byte(registrationReconcileInput))
	f.Add([]byte(registrationRequest(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 4097 {
			return
		}
		for _, mode := range []string{"preview", "register", "reconcile"} {
			r := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
			r.Header.Set("Content-Type", "application/json")
			input, ok := readRegistrationInput(httptest.NewRecorder(), r, mode)
			if !ok && (input.password != "" || input.expected != 0 || input.preview != "") {
				t.Fatal("refused request retained partial authority")
			}
		}
	})
}
