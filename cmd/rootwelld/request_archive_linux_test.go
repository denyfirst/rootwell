//go:build linux

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func requestArchiveGate(t *testing.T) (*gate, *http.Cookie) {
	t.Helper()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private fixture directory")
	}
	destination := filepath.Join(dir, "synthetic-request-archive-gate.json")
	command := exec.Command("go", "test", "../../internal/instanceaccess", "-run=^TestGenerateRequestArchiveGateFixture$", "-count=1")
	command.Env = append(os.Environ(), "ROOTWELL_REQUEST_ARCHIVE_GATE_FIXTURE="+destination)
	if command.Run() != nil {
		t.Fatal("private request gate fixture failed")
	}
	body, err := os.ReadFile(destination)
	defer clear(body)
	var input struct{ Access, Image []byte }
	if err != nil || json.Unmarshal(body, &input) != nil {
		t.Fatal("private gate fixture invalid")
	}
	defer clear(input.Access)
	defer clear(input.Image)
	path := filepath.Join(dir, "access.json")
	if os.WriteFile(path, input.Access, 0600) != nil || os.WriteFile(filepath.Join(dir, "inventory.json"), input.Image, 0600) != nil {
		t.Fatal("private gate fixture store")
	}
	g, err := newGate(path, testWorkbenchAssets(t), localHost)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"a sufficiently long installation password"}`, nil))
	return g, cookie
}

func TestLinuxRequestArchiveAPIFreshScopeAndRetainedCounts(t *testing.T) {
	g, cookie := requestArchiveGate(t)
	w := requestArchiveCall(g, "status", "{}", cookie)
	var status struct {
		Schema  string                              `json:"schema_version"`
		Saved   bool                                `json:"saved"`
		Network bool                                `json:"network_used"`
		Status  inventorystore.RequestArchiveStatus `json:"status"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.Schema != "rootwell.request-archive.v1" || status.Saved || status.Network || status.Status.Active != 16 || !status.Status.CanArchive {
		t.Fatal("request archive status refused", w.Code)
	}
	body := strings.Replace(requestArchiveBody(status.Status.Generation), nextTestPassword, "a sufficiently long installation password", 1)
	if w := requestArchiveCall(g, "archive", strings.Replace(body, "a sufficiently long installation password", "incorrect-password", 1), cookie); w.Code != 401 {
		t.Fatal("fresh password bypass", w.Code)
	}
	if w := requestArchiveCall(g, "archive", strings.Replace(body, `"backup_confirmed":true`, `"backup_confirmed":false`, 1), cookie); w.Code != 400 {
		t.Fatal("backup consent bypass", w.Code)
	}
	w = requestArchiveCall(g, "archive", body, cookie)
	var out struct {
		Saved   bool                                `json:"saved"`
		Network bool                                `json:"network_used"`
		Status  inventorystore.RequestArchiveStatus `json:"status"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Saved || out.Network || out.Status.Active != 0 || out.Status.Archived != 16 || out.Status.Generation != status.Status.Generation+1 {
		t.Fatal("valid request archive refused", w.Code)
	}
	if strings.Contains(w.Body.String(), "installation password") || strings.Contains(w.Body.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), "/acme/order/") {
		t.Fatal("archive response leaked custody content")
	}
	if w := requestArchiveCall(g, "archive", body, cookie); w.Code != 409 {
		t.Fatal("stale archive repeated", w.Code)
	}
}
