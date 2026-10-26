//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/providerretry"
	"github.com/denyfirst/rootwell/internal/renewalpolicy"
	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

func timingAPIFixture(t *testing.T) (*gate, *http.Cookie, string, string, session) {
	t.Helper()
	dir := t.TempDir()
	if os.Chmod(dir, 0o700) != nil {
		t.Fatal("private fixture directory")
	}
	destination := filepath.Join(dir, "synthetic-closed-gate.json")
	command := exec.Command("go", "test", "../../internal/instanceaccess", "-run=^TestGenerateClosedRequestGateFixture$", "-count=1")
	command.Env = append(os.Environ(), "ROOTWELL_CLOSED_GATE_FIXTURE="+destination)
	if command.Run() != nil {
		t.Fatal("private timing fixture failed")
	}
	body, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	var f struct {
		Access, Image []byte
		Fingerprint   string
	}
	if json.Unmarshal(body, &f) != nil {
		t.Fatal("invalid fixture")
	}
	path := filepath.Join(dir, "access.json")
	if os.WriteFile(path, f.Access, 0o600) != nil || os.WriteFile(filepath.Join(dir, "inventory.json"), f.Image, 0o600) != nil {
		t.Fatal("private fixture store failed")
	}
	g, err := newGate(path, testWorkbenchAssets(t), localHost)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	cookie := sessionCookie(t, call(g, "POST", "/api/session", `{"password":"`+nextTestPassword+`"}`, nil))
	r := httptest.NewRequest("GET", "http://"+localHost+"/", nil)
	r.AddCookie(cookie)
	s, ok := g.currentSession(r)
	if !ok || !s.inventoryReady {
		t.Fatal("timing session unavailable")
	}
	return g, cookie, filepath.Join(dir, "inventory.json"), f.Fingerprint, s
}

func TestLinuxRenewalTimingAPIFreshAuthPublicSourceAndNoAutomaticRenewal(t *testing.T) {
	g, cookie, store, fp, s := timingAPIFixture(t)
	defer clear(s.dataKey[:])
	before, _ := os.ReadFile(store)
	calls := 0
	g.timingConnect = func(_ context.Context, permit func() bool, der []byte) (renewalrecord.Observation, error) {
		calls++
		if !permit() {
			t.Fatal("legitimate permit refused")
		}
		image, _ := os.ReadFile(store)
		intent, gen, err := inventorystore.ReadStagingRenewalTiming(s.dataKey[:], s.installationID[:], image, 14, fp)
		if err != nil || gen != 14 || !intent.Pending {
			t.Fatal("provider before intent")
		}
		if _, _, err := instanceaccess.ReadStagingRenewalTiming(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, 14, fp); !errors.Is(err, instanceaccess.ErrAccessBusy) {
			t.Fatal("writer lock released")
		}
		cid, err := renewalpolicy.CertificateID(der)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		return renewalrecord.Observation{CertificateID: cid, Available: true, Information: renewalpolicy.Information{Window: renewalpolicy.Window{Start: now.Add(10 * time.Minute), End: now.Add(15 * time.Minute)}, CheckedAt: now, CheckAfter: now.Add(6 * time.Hour)}}, nil
	}
	read := timingBody(fp, 13, "status")
	w := timingCall(g, "status", read, cookie)
	var output timingOutput
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Generation != 13 || output.Status.Prepared || !output.Status.CanRead || output.NetworkAttempted || output.AutomaticRenewal || output.Saved || calls != 0 {
		t.Fatal("local timing status wrong", w.Code)
	}
	after, _ := os.ReadFile(store)
	if !bytes.Equal(before, after) {
		t.Fatal("status wrote image")
	}
	check := timingBody(fp, 13, "check")
	if w := timingCall(g, "check", strings.Replace(check, nextTestPassword, "wrong-secret-sentinel", 1), cookie); w.Code != 401 || calls != 0 {
		t.Fatal("wrong password reached CA")
	}
	if w := timingCall(g, "check", timingBody(fp, 12, "check"), cookie); w.Code != 409 || calls != 0 {
		t.Fatal("stale generation reached CA")
	}
	g.derive <- struct{}{}
	w = timingCall(g, "check", check, cookie)
	<-g.derive
	if w.Code != 503 || calls != 0 {
		t.Fatal("shared crypto budget bypassed")
	}
	g.directoryBusy = true
	w = timingCall(g, "check", check, cookie)
	g.directoryBusy = false
	if w.Code != 429 || calls != 0 {
		t.Fatal("shared provider budget bypassed")
	}
	w = timingCall(g, "check", check, cookie)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Schema != "rootwell.acme.renewal-timing.v1" || output.Generation != 15 || !output.Saved || !output.NetworkAttempted || output.AutomaticRenewal || output.Status.State != "ari" || calls != 1 {
		t.Fatal("scoped provider check failed", w.Code)
	}
	for _, secret := range []string{nextTestPassword, "PRIVATE KEY", "private_key", "acme/order"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("timing response leaked material")
		}
	}
	if w := timingCall(g, "check", timingBody(fp, 15, "check"), cookie); w.Code != 409 || calls != 1 {
		t.Fatal("saved provider interval bypassed")
	}
	call(g, "DELETE", "/api/session", "", cookie)
	if w := timingCall(g, "status", timingBody(fp, 15, "status"), cookie); w.Code != 401 {
		t.Fatal("logout retained timing access")
	}
}

func TestLinuxRenewalTimingAPIProviderWaitBlocksDirectoryAndLostReadRetiresLocally(t *testing.T) {
	for _, mode := range []string{"provider-wait", "lost"} {
		t.Run(mode, func(t *testing.T) {
			g, cookie, store, fp, s := timingAPIFixture(t)
			defer clear(s.dataKey[:])
			calls := 0
			g.timingConnect = func(context.Context, func() bool, []byte) (renewalrecord.Observation, error) {
				calls++
				if mode == "provider-wait" {
					return renewalrecord.Observation{}, &renewalrecord.Failure{Temporary: true, Hint: providerretry.Hint{NotBefore: time.Now().UTC().Add(3 * time.Hour)}}
				}
				return renewalrecord.Observation{CertificateID: "wrong-id-sentinel"}, nil
			}
			w := timingCall(g, "check", timingBody(fp, 13, "check"), cookie)
			var output timingOutput
			if mode == "provider-wait" {
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Generation != 15 || output.Status.State != "error" || output.Status.ProviderNotBefore == "" || output.Status.CanRead {
					t.Fatal("wait not saved", w.Code)
				}
				g.directoryLast = time.Time{}
				g.directoryCheck = func(context.Context, func() bool) (acmestaging.Summary, error) {
					t.Fatal("directory bypassed provider wait")
					return acmestaging.Summary{}, nil
				}
				if w := acmeCall(g, "POST", "/api/acme/directory", directoryConsent, cookie, "http://"+localHost, true); w.Code != 429 {
					t.Fatal("directory ignored wait", w.Code)
				}
				return
			}
			if w.Code != 503 || strings.Contains(w.Body.String(), "sentinel") {
				t.Fatal("malformed receipt published")
			}
			w = timingCall(g, "status", timingBody(fp, 14, "status"), cookie)
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || !output.Status.Pending {
				t.Fatal("lost read intent not retained")
			}
			wait, chosen := output.Status.NextCheck, output.Status.FallbackAt
			w = timingCall(g, "interrupt", timingBody(fp, 14, "interrupt"), cookie)
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil || output.Generation != 15 || output.Status.Pending || output.Status.State != "interrupted" || output.Status.NextCheck != wait || output.Status.FallbackAt != chosen || output.NetworkAttempted || !output.Saved || calls != 1 {
				t.Fatal("local retirement reset wait or contacted provider", w.Code)
			}
			image, _ := os.ReadFile(store)
			if _, _, err := inventorystore.Open(s.dataKey[:], s.installationID[:], image); err != nil {
				t.Fatal("retirement corrupted image")
			}
		})
	}
}

func TestLinuxRenewalTimingAPILogoutDuringProviderCheckRetainsOnlyIntent(t *testing.T) {
	g, cookie, store, fp, s := timingAPIFixture(t)
	defer clear(s.dataKey[:])
	g.timingConnect = func(_ context.Context, permit func() bool, der []byte) (renewalrecord.Observation, error) {
		cid, err := renewalpolicy.CertificateID(der)
		if err != nil || !permit() {
			t.Fatal("valid source unavailable")
		}
		call(g, "DELETE", "/api/session", "", cookie)
		if permit() {
			t.Fatal("logout retained provider permit")
		}
		return renewalrecord.Observation{CertificateID: cid}, nil
	}
	w := timingCall(g, "check", timingBody(fp, 13, "check"), cookie)
	if w.Code != 503 || strings.Contains(w.Body.String(), "schema_version") {
		t.Fatal("revoked result published", w.Code)
	}
	image, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	status, gen, err := inventorystore.ReadStagingRenewalTiming(s.dataKey[:], s.installationID[:], image, 14, fp)
	if err != nil || gen != 14 || !status.Pending {
		t.Fatal("revoked request lost intent", err)
	}
}
