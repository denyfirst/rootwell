//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"os"
	"strings"
	"testing"
)

func TestLinuxHistoryArchiveAPISeparateConsentAndFreshPassword(t *testing.T) {
	g, cookie, store, fp, s := timingAPIFixture(t)
	defer clear(s.dataKey[:])
	image, _ := os.ReadFile(store)
	for gen := uint64(13); gen <= 512; gen++ {
		var err error
		image, _, _, err = inventorystore.UpdateOwner(s.dataKey[:], s.installationID[:], image, fp, string(rune(1000+gen)), gen)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(store, image, 0600); err != nil {
		t.Fatal(err)
	}
	w := archiveCall(g, "status", "{}", cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"can_archive":true`) {
		t.Fatal("status refused", w.Code)
	}
	if w := archiveCall(g, "archive", archiveBody(513), nil); w.Code != 401 {
		t.Fatal("anonymous archive admitted")
	}
	if w := archiveCall(g, "archive", strings.Replace(archiveBody(513), nextTestPassword, "incorrect-password", 1), cookie); w.Code != 401 {
		t.Fatal("wrong password admitted")
	}
	if w := archiveCall(g, "archive", `{"expected_generation":513,"confirm":true}`, cookie); w.Code != 400 {
		t.Fatal("consent reused")
	}
	after, _ := os.ReadFile(store)
	if !bytes.Equal(image, after) {
		t.Fatal("rejected archive wrote")
	}
	w = archiveCall(g, "archive", archiveBody(513), cookie)
	if w.Code != 200 {
		t.Fatal("valid archive refused", w.Code, w.Body.String())
	}
	var out struct {
		Saved  bool                                `json:"saved"`
		Status inventorystore.HistoryArchiveStatus `json:"status"`
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Saved || out.Status.Generation != 514 || out.Status.Active != 1 || out.Status.Archived != 512 {
		t.Fatal("incorrect archive response")
	}
	if strings.Contains(w.Body.String(), nextTestPassword) || strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("archive output leaked secret")
	}
	if w := archiveCall(g, "archive", archiveBody(513), cookie); w.Code != 409 {
		t.Fatal("stale request admitted", w.Code)
	}
}
