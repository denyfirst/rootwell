package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func TestInventoryInputRejectsDuplicateUnknownAndOversizedJSON(t *testing.T) {
	for _, tc := range []struct {
		body, contentType string
		want              int
	}{
		{`{"certificate":"AA==","owner":"A","location":"B"}`, "application/json", 0},
		{`{"certificate":"AA==","certificate":"AA=="}`, "application/json", http.StatusBadRequest},
		{`{"certificate":"AA==","secret":"bad"}`, "application/json", http.StatusBadRequest},
		{`{"certificate":"AA=="} {}`, "application/json", http.StatusBadRequest},
		{`{"certificate":""}`, "application/json", http.StatusBadRequest},
		{`{"certificate":"AA=="}`, "text/plain", http.StatusUnsupportedMediaType},
	} {
		r := httptest.NewRequest("POST", "http://localhost/api/inventory", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.contentType)
		w := httptest.NewRecorder()
		input, ok := readInventoryInput(w, r)
		if tc.want == 0 {
			if !ok || !bytes.Equal(input.Certificate, []byte{0}) {
				t.Fatalf("valid input refused: %d", w.Code)
			}
		} else if ok || w.Code != tc.want {
			t.Fatalf("invalid body accepted: %d, want %d", w.Code, tc.want)
		}
	}
	r := httptest.NewRequest("POST", "http://localhost/api/inventory", strings.NewReader(`{"certificate":"`+strings.Repeat("A", maxInventoryRequest)+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	if _, ok := readInventoryInput(w, r); ok || w.Code != http.StatusBadRequest {
		t.Fatal("oversized body accepted")
	}
}

func TestInventoryOutputNeverSerializesCertificateBytes(t *testing.T) {
	w := httptest.NewRecorder()
	writeInventoryJSON(w, http.StatusOK, []publicinventory.Record{{Fingerprint: "fingerprint", DER: []byte("secret-certificate-source-bytes"), Subject: "subject", ImportGeneration: 2}}, 2)
	if w.Code != http.StatusOK || bytes.Contains(w.Body.Bytes(), []byte("secret-certificate-source-bytes")) || !strings.Contains(w.Body.String(), `"verification":"not-performed"`) {
		t.Fatal("inventory response leaked DER or misreported verification")
	}
}
