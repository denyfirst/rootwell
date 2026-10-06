package main

import (
	"errors"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func TestBackgroundMonitorWithoutBrowserExpiresClearsAndRejectsLateLogout(t *testing.T) {
	g, _ := testGate(t)
	revision, err := instanceaccess.Revision(g.accessPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	identity := [32]byte{1}
	s := session{revision: revision, inventoryReady: true, expires: now.Add(12 * time.Hour), dataKey: [32]byte{9}, installationID: [16]byte{8}}
	g.sessions[identity] = s
	fp := "AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA"
	reads := 0
	g.monitorRead = func(input session) ([]publicinventory.Record, uint64, error) {
		reads++
		if input.dataKey != s.dataKey {
			t.Error("wrong monitoring key")
		}
		return []publicinventory.Record{{Fingerprint: fp, NotBefore: "2020-01-01T00:00:00Z", NotAfter: "2026-10-07T12:00:00Z"}}, 2, nil
	}
	g.tickMonitor(now) // No HTTP or browser interaction.
	state := g.monitorSnapshot(now, 2)
	if reads != 1 || state.Status != "ready" || len(state.Attention) != 1 || state.Attention[0] != fp {
		t.Fatal("background check failed")
	}
	state.Attention[0] = "changed"
	if g.monitorSnapshot(now, 2).Attention[0] != fp {
		t.Fatal("snapshot aliases memory")
	}
	if g.monitorSnapshot(now, 3).Status != "stale" || g.monitorSnapshot(now.Add(2*time.Minute), 2).Status != "stale" {
		t.Fatal("stale observation is healthy")
	}
	g.tickMonitor(now.Add(-time.Second))
	if g.monitorSnapshot(now, 2).Status != "clock-unavailable" {
		t.Fatal("backwards clock accepted")
	}
	g.tickMonitor(now)
	now = now.Add(12 * time.Hour)
	g.tickMonitor(now)
	if len(g.sessions) != 0 || g.monitorSnapshot(now, 2).Status != "locked" || reads != 2 {
		t.Fatal("expired session extended or old reminder retained")
	}
	now = now.Add(time.Minute)
	s.expires = now.Add(time.Hour)
	g.sessions[identity] = s
	g.monitorRead = func(session) ([]publicinventory.Record, uint64, error) {
		return nil, 0, errors.New("secret-looking internal error")
	}
	g.tickMonitor(now)
	if g.monitorSnapshot(now, 2).Status != "unavailable" || len(g.monitorSnapshot(now, 2).Attention) != 0 {
		t.Fatal("storage error retained healthy results")
	}
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	g.monitorRead = func(session) ([]publicinventory.Record, uint64, error) {
		close(started)
		<-release
		return []publicinventory.Record{{Fingerprint: fp, NotBefore: "2020-01-01T00:00:00Z", NotAfter: "2026-10-07T12:00:00Z"}}, 2, nil
	}
	go func() { g.tickMonitor(now); close(finished) }()
	<-started
	g.revokeAll(httptest.NewRecorder())
	close(release)
	<-finished
	if g.monitorSnapshot(now, 2).Status != "locked" || len(g.monitorSnapshot(now, 2).Attention) != 0 {
		t.Fatal("logout published late result")
	}
	// The actual worker starts on its own, without a page timer or request.
	g.sessions[identity] = s
	workerRead := make(chan struct{})
	g.monitorRead = func(session) ([]publicinventory.Record, uint64, error) { close(workerRead); return nil, 2, nil }
	g.startMonitor()
	select {
	case <-workerRead:
	case <-time.After(3 * time.Second):
		t.Fatal("daemon never scheduled independently")
	}
}

func TestBackgroundMonitorInvalidRevisionClearsSessionsAndLateResult(t *testing.T) {
	g, _ := testGate(t)
	revision, err := instanceaccess.Revision(g.accessPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	g.now = func() time.Time { return now }
	id := [32]byte{4}
	s := session{revision: revision, inventoryReady: true, expires: now.Add(time.Hour), dataKey: [32]byte{6}}
	g.sessions[id] = s
	access, err := os.ReadFile(g.accessPath)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := func() {
		if err := os.WriteFile(g.accessPath, []byte("not an access file"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g.monitorRead = func(session) ([]publicinventory.Record, uint64, error) {
		corrupt() // Revocation/replacement between authenticated read and publish.
		return nil, 2, nil
	}
	g.tickMonitor(now)
	if state := g.monitorSnapshot(now, 2); state.Status != "unavailable" || len(state.Attention) != 0 {
		t.Fatal("changed revision published late result")
	}
	g.monitorRead = func(session) ([]publicinventory.Record, uint64, error) {
		t.Fatal("invalid revision reached inventory read")
		return nil, 0, nil
	}
	g.tickMonitor(now)
	if len(g.sessions) != 0 || g.monitorSnapshot(now, 2).Status != "locked" {
		t.Fatal("invalid access kept session keys or healthy result")
	}
	if err := os.WriteFile(g.accessPath, access, 0o600); err != nil {
		t.Fatal(err)
	}
	g.sessions[id] = s
	if err := os.Rename(g.accessPath, g.accessPath+".held"); err != nil {
		t.Fatal(err)
	}
	g.tickMonitor(now)
	if len(g.sessions) != 0 || g.monitorSnapshot(now, 2).Status != "unavailable" {
		t.Fatal("unreadable revision kept session keys or healthy result")
	}
	if err := os.Rename(g.accessPath+".held", g.accessPath); err != nil {
		t.Fatal(err)
	}
	g.tickMonitor(now)
	if g.monitorSnapshot(now, 2).Status != "locked" {
		t.Fatal("repaired access silently restored unlock")
	}
}
