package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func renewalRequest(gen, fingerprint string) string {
	return strings.TrimSuffix(orderRequest(gen, false), "}") + `,"fingerprint":"` + fingerprint + `"}`
}

func TestRenewalRequestStrictShapeNoPartialSelection(t *testing.T) {
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
}
