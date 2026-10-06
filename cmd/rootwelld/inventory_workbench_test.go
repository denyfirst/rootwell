package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func TestWorkbenchSelectionIsExactBoundedAndNonUploading(t *testing.T) {
	valid := "fingerprint=" + strings.Repeat("AB%3A", 31) + "AB&expected_generation=2&tool=inspect"
	for _, body := range []string{valid, strings.Replace(valid, "inspect", "verify", 1)} {
		r := httptest.NewRequest("POST", "/workbench", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		fp, gen, tool, ok := readWorkbenchSelection(w, r)
		if !ok || fp != strings.Repeat("AB:", 31)+"AB" || gen != 2 || (tool != "inspect" && tool != "verify") {
			t.Fatal("valid explicit selection refused")
		}
	}
	for _, body := range []string{
		valid + "&tool=verify", valid + "&certificate=secret", valid + "&owner=private-note",
		strings.Replace(valid, "generation=2", "generation=02", 1), strings.Replace(valid, "generation=2", "generation=0", 1),
		strings.Replace(valid, "generation=2", "generation=9007199254740992", 1),
		strings.Replace(valid, "inspect", "convert", 1), strings.ReplaceAll(valid, "AB", "ab"),
		strings.Replace(valid, "AB", "GG", 1), valid + "%ZZ", strings.Repeat("x", 1025),
		"fingerprint=%FF&expected_generation=2&tool=inspect", "tool=inspect",
	} {
		r := httptest.NewRequest("POST", "/workbench", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		if _, _, _, ok := readWorkbenchSelection(w, r); ok || w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "secret") {
			t.Fatal("unsafe form accepted or input echoed")
		}
	}
	r := httptest.NewRequest("POST", "/workbench", strings.NewReader(valid))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	if _, _, _, ok := readWorkbenchSelection(w, r); ok || w.Code != http.StatusUnsupportedMediaType {
		t.Fatal("non-form accepted")
	}
}

func TestInventoryWorkbenchRefusesBeforeStoredDataRead(t *testing.T) {
	for _, tc := range []struct {
		s        session
		signedIn bool
		want     int
	}{
		{session{}, false, http.StatusUnauthorized},
		{session{setup: true}, true, http.StatusForbidden},
		{session{}, true, func() int {
			if runtime.GOOS == "linux" {
				return http.StatusConflict
			}
			return http.StatusNotImplemented
		}()},
	} {
		w := httptest.NewRecorder()
		(&gate{}).inventoryWorkbenchEndpoint(w, httptest.NewRequest("POST", "/workbench", nil), tc.s, tc.signedIn)
		if w.Code != tc.want || strings.Contains(w.Body.String(), "inventory-source") {
			t.Fatal("authority/platform guard failed")
		}
	}
}

func TestInventoryWorkbenchHTMLContainsOnlySelectedPublicObject(t *testing.T) {
	assets := t.TempDir()
	index := filepath.Join(assets, "index.html")
	if err := os.WriteFile(index, []byte("<body>"+inventoryWorkbenchMarker+"</body>"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(assets)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	g := &gate{assets: root}
	cert, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	catalog := &publicinventory.Catalog{}
	records, err := catalog.Add(cert, "never-export-owner", "never-export-location")
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"inspect", "verify"} {
		w := httptest.NewRecorder()
		g.writeInventoryWorkbench(w, records[0], tool)
		if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "text/html") ||
			strings.Contains(w.Body.String(), "never-export") || strings.Contains(w.Body.String(), "PRIVATE KEY") {
			t.Fatal("handoff leaked notes or failed")
		}
		payload := strings.TrimSuffix(strings.TrimPrefix(w.Body.String(), `<body><div id="inventory-source" hidden>`), "</div></body>")
		var got struct {
			Schema      string `json:"schema_version"`
			Fingerprint string `json:"fingerprint"`
			DER         []byte `json:"der"`
			Tool        string `json:"tool"`
		}
		if json.Unmarshal([]byte(payload), &got) != nil || !bytes.Equal(got.DER, records[0].DER) ||
			got.Fingerprint != records[0].Fingerprint || got.Tool != tool || got.Schema != "rootwell.inventory.workbench.v1" {
			t.Fatal("public object changed in HTML")
		}
	}
	for _, body := range []string{"no marker", inventoryWorkbenchMarker + inventoryWorkbenchMarker, strings.Repeat("x", (1<<20)+1)} {
		if err := os.WriteFile(index, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		g.writeInventoryWorkbench(w, records[0], "inspect")
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), records[0].Fingerprint) {
			t.Fatal("unsafe template released data")
		}
	}
}
