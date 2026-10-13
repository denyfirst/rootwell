package main

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func renewalRequest(gen, fingerprint string) string {
	return strings.TrimSuffix(orderRequest(gen, false), "}") + `,"fingerprint":"` + fingerprint + `"}`
}

func TestRenewalRequestAndNavigationStrictShapeNoPartialSelection(t *testing.T) {
	fp := strings.Repeat("AB:", 31) + "AB"
	for _, body := range []string{renewalRequest("14", fp), strings.TrimSuffix(renewalRequest("14", fp), "}") + `,"domains":["evil.example.com"]}`, strings.Replace(renewalRequest("14", fp), fp, "invalid", 1), strings.TrimSuffix(renewalRequest("14", fp), "}") + `,"fingerprint":"` + fp + `"}`} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		input, ok := readOrderInput(httptest.NewRecorder(), r, "renew")
		want := body == renewalRequest("14", fp)
		if ok != want || !ok && (input.Fingerprint != "" || input.Password != "" || input.Expected != 0) {
			t.Fatal("partial/invalid renewal request")
		}
	}
	for _, fields := range []url.Values{{"fingerprint": {fp}, "expected_generation": {"14"}, "tool": {"renew"}}, {"fingerprint": {fp, fp}, "expected_generation": {"14"}, "tool": {"renew"}}, {"fingerprint": {fp}, "expected_generation": {"014"}, "tool": {"renew"}}, {"fingerprint": {fp}, "expected_generation": {"14"}, "tool": {"inspect"}}, {"fingerprint": {fp}, "expected_generation": {"14"}, "tool": {"renew"}, "private_key": {"sentinel"}}} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(fields.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		got, gen, tool, ok := readPublicNavigationSelection(httptest.NewRecorder(), r, true)
		want := len(fields) == 3 && len(fields["fingerprint"]) == 1 && fields.Get("expected_generation") == "14" && fields.Get("tool") == "renew"
		if ok != want || !ok && (got != "" || gen != 0 || tool != "") {
			t.Fatal("partial/invalid renewal navigation")
		}
	}
}
