package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func TestSavedWebsiteSelectionCannotAddTargetSecretsOrOtherTools(t *testing.T) {
	valid := "fingerprint=" + strings.Repeat("AB%3A", 31) + "AB&expected_generation=2&tool=website-check"
	for _, body := range []string{valid, valid + "&target=secret-sentinel", valid + "&password=secret-sentinel", valid + "&certificate=secret-sentinel", valid + "&tool=website-check", strings.Replace(valid, "website-check", "inspect", 1), strings.Replace(valid, "website-check", "renew", 1), strings.Replace(valid, "generation=2", "generation=02", 1), strings.ReplaceAll(valid, "AB", "ab"), strings.Repeat("x", 1025)} {
		r := httptest.NewRequest("POST", "/website-check/saved", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		_, gen, tool, ok := readNavigationSelection(w, r, "website-check")
		if ok != (body == valid) || (ok && (gen != 2 || tool != "website-check")) || strings.Contains(w.Body.String(), "secret-sentinel") {
			t.Fatal("selection accepted extra authority or leaked input")
		}
	}
}

func TestSavedWebsiteHTMLTransfersOnlyOnePublicSnapshot(t *testing.T) {
	input, err := os.ReadFile("../../web/workbench/rootwell-demo-bundle.pem")
	if err != nil {
		t.Fatal(err)
	}
	catalog := &publicinventory.Catalog{}
	records, err := catalog.Add(input, "never-transfer-owner", "never-transfer-location")
	if err != nil || len(records) < 2 {
		t.Fatal("fixture unavailable", err)
	}
	w := httptest.NewRecorder()
	writeSavedWebsite(w, records[0], 2)
	if w.Code != 200 || strings.Contains(w.Body.String(), "never-transfer") || strings.Contains(w.Body.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), records[1].Fingerprint) {
		t.Fatal("wrong or non-public material in handoff")
	}
	prefix := `<div id="website-saved-source" hidden>`
	_, after, ok := strings.Cut(w.Body.String(), prefix)
	if !ok {
		t.Fatal("missing source")
	}
	data, _, ok := strings.Cut(after, "</div>")
	var got struct {
		Schema      string `json:"schema_version"`
		Fingerprint string `json:"fingerprint"`
		Generation  uint64 `json:"generation"`
		DER         []byte `json:"der"`
	}
	var keys map[string]json.RawMessage
	if !ok || json.Unmarshal([]byte(data), &got) != nil || json.Unmarshal([]byte(data), &keys) != nil || len(keys) != 4 || got.Schema != "rootwell.website-saved.v1" || got.Fingerprint != records[0].Fingerprint || got.Generation != 2 || !bytes.Equal(got.DER, records[0].DER) {
		t.Fatal("public snapshot identity changed")
	}
	wrong := records[0]
	wrong.Fingerprint = strings.Repeat("00:", 31) + "00"
	malformed := records[0]
	malformed.DER = []byte("secret-sentinel")
	caBytes, err := os.ReadFile("../../web/workbench/rootwell-verify-demo-root.pem")
	if err != nil {
		t.Fatal(err)
	}
	caRecords, err := catalog.Add(caBytes, "", "")
	if err != nil || len(caRecords) != 1 {
		t.Fatal("CA fixture unavailable", err)
	}
	for _, r := range []publicinventory.Record{wrong, malformed, caRecords[0]} {
		out := httptest.NewRecorder()
		writeSavedWebsite(out, r, 2)
		if out.Code < 400 || strings.Contains(out.Body.String(), "website-saved-source") || strings.Contains(out.Body.String(), "secret-sentinel") {
			t.Fatal("invalid or CA record released")
		}
	}
}

func TestSavedWebsiteNavigationRefusesBeforeRead(t *testing.T) {
	for _, tc := range []struct {
		method string
		signed bool
		s      session
		want   int
	}{
		{"GET", false, session{}, 405}, {"HEAD", true, session{}, 405}, {"POST", false, session{}, 401}, {"POST", true, session{setup: true}, 403}, {"POST", true, session{}, 403},
	} {
		w := httptest.NewRecorder()
		(&gate{}).savedWebsiteEndpoint(w, httptest.NewRequest(tc.method, "/website-check/saved", nil), tc.s, tc.signed)
		if w.Code != tc.want || strings.Contains(w.Body.String(), "website-saved-source") {
			t.Fatal("navigation guard failed")
		}
	}
}
