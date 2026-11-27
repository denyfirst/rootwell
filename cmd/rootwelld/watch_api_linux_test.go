//go:build linux

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/watchstore"
	"github.com/denyfirst/rootwell/internal/websitechain"
	"github.com/denyfirst/rootwell/internal/websiteprobe"
)

func watched(t *testing.T, e *testEnv, cookie *http.Cookie) []watchstore.Site {
	t.Helper()
	w := apiCall(e.g, "GET", "/api/watch", "", cookie, "", true)
	var out watchOutput
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("watch list: %d %s", w.Code, w.Body)
	}
	return out.Sites
}

func TestLinuxASiteIsWatchedInCheckFormAndStoppingNeedsAFreshCode(t *testing.T) {
	_, cookie, e := readyGate(t)
	if sites := watched(t, e, cookie); len(sites) != 0 {
		t.Fatalf("a new vault watches %v", sites)
	}
	if w := post(t, e, cookie, "/api/watch/add", map[string]any{"target": "https://Shop.Example:443"}); w.code != http.StatusCreated {
		t.Fatalf("watch: %d %s", w.code, w.body)
	}
	if w := post(t, e, cookie, "/api/watch/add", map[string]any{"target": "shop.example"}); w.code != http.StatusConflict {
		t.Fatalf("watched twice: %d %s", w.code, w.body)
	}
	if w := post(t, e, cookie, "/api/watch/add", map[string]any{"target": "intranet.lab:8443"}); w.code != http.StatusCreated {
		t.Fatalf("watch with a port: %d %s", w.code, w.body)
	}
	for _, bad := range []string{"localhost", "shop.example/path", "user@shop.example", "127.0.0.1", ""} {
		if w := post(t, e, cookie, "/api/watch/add", map[string]any{"target": bad}); w.code != http.StatusBadRequest {
			t.Fatalf("%q was watched: %d %s", bad, w.code, w.body)
		}
	}
	if sites := watched(t, e, cookie); len(sites) != 2 || sites[0].Target != "intranet.lab:8443" || sites[1].Target != "shop.example" {
		t.Fatalf("the list: %+v", sites)
	}
	if w := apiCall(e.g, "POST", "/api/watch/add", `{"target":"x.example"}`, cookie, "https://evil.invalid", true); w.Code != http.StatusForbidden {
		t.Fatalf("another site: %d", w.Code)
	}
	if w := apiCall(e.g, "POST", "/api/watch/add", `{"target":"x.example","extra":1}`, cookie, "https://"+localHost, true); w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown field: %d", w.Code)
	}
	e.clock.add(freshLife)
	if w := post(t, e, cookie, "/api/watch/remove", map[string]any{"target": "shop.example"}); w.code != http.StatusPreconditionRequired {
		t.Fatalf("stop watching without a fresh code: %d %s", w.code, w.body)
	}
	fresh := apiCall(e.g, "POST", "/api/fresh", `{"code":"`+e.code(t)+`"}`, cookie, "https://"+localHost, true)
	if fresh.Code != http.StatusNoContent {
		t.Fatalf("fresh code: %d", fresh.Code)
	}
	cookie = sessionCookie(t, fresh)
	if w := post(t, e, cookie, "/api/watch/remove", map[string]any{"target": "shop.example"}); w.code != http.StatusNoContent {
		t.Fatalf("stop watching: %d %s", w.code, w.body)
	}
	if sites := watched(t, e, cookie); len(sites) != 1 {
		t.Fatalf("after stopping: %+v", sites)
	}
}

func TestLinuxWatchedSitesAreCheckedEverySixHoursAsWebsiteCheckDoes(t *testing.T) {
	g, cookie, e := readyGate(t)
	for _, target := range []string{"shop.example", "down.example"} {
		if w := post(t, e, cookie, "/api/watch/add", map[string]any{"target": target}); w.code != http.StatusCreated {
			t.Fatalf("watch %s: %d", target, w.code)
		}
	}
	leaf := "AA"
	var checked []string
	var last time.Time
	g.websiteCheck = func(ctx context.Context, target websiteprobe.Target, _ []*x509.Certificate, permit func() bool) (websitechain.Report, error) {
		if !permit() {
			t.Fatal("a watched check without permission")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > websiteprobe.Timeout+time.Second {
			t.Fatal("no deadline")
		}
		g.mu.Lock()
		busy, at := g.websiteBusy, g.websiteLast
		g.mu.Unlock()
		if !busy || (!last.IsZero() && at.Sub(last) < websiteGap) {
			t.Fatal("a watched check did not take Website check's turn")
		}
		last = at
		checked = append(checked, target.String())
		if target.Host == "down.example" {
			return websitechain.Report{}, &websiteprobe.Failure{Err: websiteprobe.ErrRefused, Address: "192.0.2.7"}
		}
		return websitechain.Report{State: "verified", Presented: []websitechain.Certificate{{Fingerprint: leaf, Subject: "shop.example", NotAfter: "2027-01-01T00:00:00Z", Position: 1}}}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// The turn waits for the 5-second gap on the real clock; the test clock
	// starts far enough apart.
	g.now = func() time.Time { return time.Now() }
	if err := g.checkWatched(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Join(checked, ",") != "down.example,shop.example" {
		t.Fatalf("checked %v", checked)
	}
	sites, err := g.watches.List()
	if err != nil || sites[0].State != "unreachable" || !strings.Contains(sites[0].Problem, "Nothing answers on port 443 at 192.0.2.7") || sites[1].State != "verified" || sites[1].Leaf != "AA" {
		t.Fatalf("recorded %+v", sites)
	}
	// Within six hours, nothing is checked again.
	if err := g.checkWatched(ctx); err != nil || len(checked) != 2 {
		t.Fatalf("checked again: %v %v", checked, err)
	}
}

func TestAWatchMessageSaysWhatChanged(t *testing.T) {
	link := siteLink("rootwell.lab.test:4180")
	subject, text := watchMessage(watchstore.Change{NewCertificate: true, PreviousEnd: "2026-12-01T00:00:00Z",
		Site: watchstore.Site{Target: "shop.example", LeafName: "shop.example", NotAfter: "2027-03-01T00:00:00Z"}}, link)
	if subject != "Rootwell: shop.example now serves another certificate" ||
		!strings.Contains(text, "shop.example now serves shop.example, until 1 Mar 2027. The one it served before ended 1 Dec 2026.") ||
		!strings.Contains(text, "https://rootwell.lab.test:4180/website-check#shop.example") ||
		!strings.Contains(text, "Rootwell checks this website every six hours") {
		t.Fatalf("%s\n%s", subject, text)
	}
	subject, text = watchMessage(watchstore.Change{NewProblem: true, Site: watchstore.Site{Target: "intranet.lab:8443", Problem: "The chain is incomplete"}}, siteLink(""))
	if subject != "Rootwell: intranet.lab:8443 has a problem" || !strings.HasPrefix(text, "The chain is incomplete\n") || strings.Contains(text, "https://") {
		t.Fatalf("%s\n%s", subject, text)
	}
}
