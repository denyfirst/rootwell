package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denyfirst/rootwell/internal/publicinventory"
)

// A save is confirmed only to the signed-in session that asked for it. Once
// that session is gone, changed or cancelled, the answer is "outcome
// uncertain", never a refusal that would invite a blind second save.
func TestCertificateSavePublicationNeedsCurrentSessionAndCancellation(t *testing.T) {
	e := newTestEnv(t).withAccount(t)
	input := testCertificate(t)
	catalog := &publicinventory.Catalog{}
	records, err := catalog.Add(input, "", "")
	if err != nil || len(records) != 1 {
		t.Fatal("public fixture unavailable", err)
	}
	for _, mode := range []string{"ready", "anonymous", "code stage", "expired", "different revision", "different account", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			ready := e.signIn(t)
			r := httptest.NewRequest("POST", "/api/certificates/save", nil)
			r.AddCookie(ready)
			_, original, ok := e.g.currentSession(r, false)
			if !ok || original.stage != stageReady {
				t.Fatal("the signed-in session was not found")
			}
			r = httptest.NewRequest("POST", "/api/certificates/save", nil)
			switch mode {
			case "anonymous":
			case "code stage":
				r.AddCookie(e.passwordStep(t, testPassword))
			default:
				r.AddCookie(ready)
			}
			switch mode {
			case "expired":
				e.clock.add(idleLife)
			case "different revision":
				original.revision++
			case "different account":
				original.name = "bob"
			case "canceled":
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			out := httptest.NewRecorder()
			e.g.publishCertificateSave(out, r, original, records[0], 2)
			if mode == "ready" {
				if out.Code != http.StatusCreated || !strings.Contains(out.Body.String(), records[0].Fingerprint) {
					t.Fatalf("valid save confirmation refused: %d", out.Code)
				}
				return
			}
			if out.Code != http.StatusServiceUnavailable || !strings.Contains(out.Body.String(), "outcome uncertain") || strings.Contains(out.Body.String(), records[0].Fingerprint) {
				t.Fatalf("lost publication authority falsely confirmed or classified as no write: %d %s", out.Code, out.Body)
			}
		})
	}
}
