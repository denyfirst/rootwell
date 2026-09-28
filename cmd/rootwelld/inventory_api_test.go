package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
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
	writeInventoryJSON(w, http.StatusOK, []publicinventory.Record{{Fingerprint: "fingerprint", DER: []byte("secret-certificate-source-bytes"), Subject: "subject", Locations: []string{"one", "two"}, ImportGeneration: 2}}, 3)
	if w.Code != http.StatusOK || bytes.Contains(w.Body.Bytes(), []byte("secret-certificate-source-bytes")) ||
		!strings.Contains(w.Body.String(), `"verification":"not-performed"`) || !strings.Contains(w.Body.String(), `"locations":["one","two"]`) {
		t.Fatal("inventory response leaked DER or misreported verification")
	}
}

func TestLocationInputRejectsMalformedAndDuplicateFields(t *testing.T) {
	for _, tc := range []struct {
		body, contentType string
		want              int
	}{
		{`{"fingerprint":"abc","location":"host/a","expected_generation":2}`, "application/json", 0},
		{`{"fingerprint":"abc","location":"a","location":"b","expected_generation":2}`, "application/json", http.StatusBadRequest},
		{`{"fingerprint":"abc","location":"a","expected_generation":2,"secret":"x"}`, "application/json", http.StatusBadRequest},
		{`{"fingerprint":"abc","location":"a","expected_generation":2} trailing`, "application/json", http.StatusBadRequest},
		{`{"fingerprint":"abc","location":"a","expected_generation":0}`, "application/json", http.StatusBadRequest},
		{`{"fingerprint":"abc","location":"a","expected_generation":2}`, "text/plain", http.StatusUnsupportedMediaType},
		{string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}), "application/json", http.StatusBadRequest},
		{strings.Repeat("x", 1025), "application/json", http.StatusBadRequest},
	} {
		r := httptest.NewRequest("POST", "http://localhost/api/inventory/locations", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.contentType)
		w := httptest.NewRecorder()
		input, ok := readInventoryLocationInput(w, r)
		if tc.want == 0 {
			if !ok || input.Fingerprint != "abc" || input.Location != "host/a" || input.ExpectedGeneration != 2 {
				t.Fatalf("valid location refused: %d", w.Code)
			}
		} else if ok || w.Code != tc.want {
			t.Fatalf("invalid location body accepted: %d want %d", w.Code, tc.want)
		}
	}
}

func TestOwnerInputRequiresExplicitBoundedStringAndGeneration(t *testing.T) {
	for _, tc := range []struct {
		body, contentType string
		want              int
		owner             string
	}{
		{`{"fingerprint":"abc","owner":"Security","expected_generation":2}`, "application/json", 0, "Security"},
		{`{"fingerprint":"abc","owner":  "Security","expected_generation":2}`, "application/json", 0, "Security"},
		{`{"fingerprint":"abc","owner":"","expected_generation":2}`, "application/json", 0, ""},
		{`{"fingerprint":"abc","owner":null,"expected_generation":2}`, "application/json", http.StatusBadRequest, ""},
		{`{"fingerprint":"abc","owner":"A","owner":"B","expected_generation":2}`, "application/json", http.StatusBadRequest, ""},
		{`{"fingerprint":"abc","owner":"A","expected_generation":2,"secret":"x"}`, "application/json", http.StatusBadRequest, ""},
		{`{"fingerprint":"abc","owner":"A","expected_generation":2} trailing`, "application/json", http.StatusBadRequest, ""},
		{`{"fingerprint":"abc","owner":"A","expected_generation":0}`, "application/json", http.StatusBadRequest, ""},
		{`{"fingerprint":"abc","owner":"bad\nowner","expected_generation":2}`, "application/json", http.StatusBadRequest, ""},
		{`{"fingerprint":"abc","owner":"A","expected_generation":2}`, "text/plain", http.StatusUnsupportedMediaType, ""},
		{string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}), "application/json", http.StatusBadRequest, ""},
		{strings.Repeat("x", 1025), "application/json", http.StatusBadRequest, ""},
	} {
		r := httptest.NewRequest("POST", "http://localhost/api/inventory/owner", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.contentType)
		w := httptest.NewRecorder()
		input, ok := readInventoryOwnerInput(w, r)
		if tc.want == 0 {
			if !ok || input.Fingerprint != "abc" || input.Owner != tc.owner || input.ExpectedGeneration != 2 {
				t.Fatalf("valid owner input refused: %d", w.Code)
			}
		} else if ok || w.Code != tc.want {
			t.Fatalf("invalid owner input accepted: %d want %d", w.Code, tc.want)
		}
	}
}

func TestLocationChangeInputRequiresExactActionAndFields(t *testing.T) {
	for _, tc := range []struct {
		body, media string
		want        int
		action      inventorystore.LocationChange
	}{
		{`{"fingerprint":"abc","old_location":"first","new_location":"primary","action":"rename","expected_generation":3}`, "application/json", 0, inventorystore.LocationRename},
		{`{"fingerprint":"abc","old_location":"first","action":"remove","expected_generation":3}`, "application/json", 0, inventorystore.LocationRemove},
		{`{"fingerprint":"abc","old_location":"first","action":"remove","new_location":"","expected_generation":3}`, "application/json", http.StatusBadRequest, 0},
		{`{"fingerprint":"abc","old_location":"first","action":"rename","expected_generation":3}`, "application/json", http.StatusBadRequest, 0},
		{`{"fingerprint":"abc","old_location":"first","new_location":"bad\nlabel","action":"rename","expected_generation":3}`, "application/json", http.StatusBadRequest, 0},
		{`{"fingerprint":"abc","old_location":"first","action":"unknown","expected_generation":3}`, "application/json", http.StatusBadRequest, 0},
		{`{"fingerprint":"abc","old_location":"first","action":"remove","action":"rename","expected_generation":3}`, "application/json", http.StatusBadRequest, 0},
		{`{"fingerprint":"abc","old_location":"first","action":"remove","expected_generation":3,"unknown":1}`, "application/json", http.StatusBadRequest, 0},
		{`{"fingerprint":"abc","old_location":"first","action":"remove","expected_generation":0}`, "application/json", http.StatusBadRequest, 0},
		{`{"fingerprint":"abc","old_location":"first","action":"remove","expected_generation":3} trailing`, "application/json", http.StatusBadRequest, 0},
		{`{"fingerprint":"abc","old_location":"first","action":"remove","expected_generation":3}`, "text/plain", http.StatusUnsupportedMediaType, 0},
		{strings.Repeat("x", 1025), "application/json", http.StatusBadRequest, 0},
	} {
		r := httptest.NewRequest("POST", "http://localhost/api/inventory/locations/change", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.media)
		w := httptest.NewRecorder()
		input, ok := readInventoryLocationChangeInput(w, r)
		if tc.want == 0 {
			if !ok || input.Fingerprint != "abc" || input.OldLocation != "first" || input.Action != tc.action || input.ExpectedGeneration != 3 {
				t.Fatalf("valid location change refused: %d", w.Code)
			}
		} else if ok || w.Code != tc.want {
			t.Fatalf("invalid location change accepted: %d want %d", w.Code, tc.want)
		}
	}
}

func TestInventoryDeleteInputRequiresTypedFingerprintConfirmationAndGeneration(t *testing.T) {
	for _, tc := range []struct {
		body, media string
		want        int
	}{
		{`{"fingerprint":"abc","typed_fingerprint":"abc","confirmation":"delete-public-record","expected_generation":3}`, "application/json", 0},
		{`{"fingerprint":"abc","typed_fingerprint":"xyz","confirmation":"delete-public-record","expected_generation":3}`, "application/json", http.StatusBadRequest},
		{`{"fingerprint":"abc","confirmation":"delete-public-record","expected_generation":3}`, "application/json", http.StatusBadRequest},
		{`{"fingerprint":"abc","typed_fingerprint":"abc","expected_generation":3}`, "application/json", http.StatusBadRequest},
		{`{"fingerprint":"abc","typed_fingerprint":"abc","confirmation":"yes","expected_generation":3}`, "application/json", http.StatusBadRequest},
		{`{"fingerprint":"abc","typed_fingerprint":"abc","confirmation":"delete-public-record","expected_generation":0}`, "application/json", http.StatusBadRequest},
		{`{"fingerprint":"abc","fingerprint":"abc","typed_fingerprint":"abc","confirmation":"delete-public-record","expected_generation":3}`, "application/json", http.StatusBadRequest},
		{`{"fingerprint":"abc","typed_fingerprint":"abc","confirmation":"delete-public-record","expected_generation":3,"unknown":1}`, "application/json", http.StatusBadRequest},
		{`{"fingerprint":"abc","typed_fingerprint":"abc","confirmation":"delete-public-record","expected_generation":3} trailing`, "application/json", http.StatusBadRequest},
		{`{"fingerprint":"abc","typed_fingerprint":"abc","confirmation":"delete-public-record","expected_generation":3}`, "text/plain", http.StatusUnsupportedMediaType},
		{strings.Repeat("x", 1025), "application/json", http.StatusBadRequest},
	} {
		r := httptest.NewRequest("POST", "http://localhost/api/inventory/delete", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.media)
		w := httptest.NewRecorder()
		input, ok := readInventoryDeleteInput(w, r)
		if tc.want == 0 {
			if !ok || input.Fingerprint != "abc" || input.TypedFingerprint != "abc" || input.ExpectedGeneration != 3 {
				t.Fatalf("valid delete input refused: %d", w.Code)
			}
		} else if ok || w.Code != tc.want {
			t.Fatalf("invalid delete input accepted: %d want %d", w.Code, tc.want)
		}
	}
}
