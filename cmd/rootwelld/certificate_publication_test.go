package main

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func TestCertificateSavePublicationNeedsCurrentSessionAndCancellation(t *testing.T) {
	g, _ := testGate(t)
	revision, err := instanceaccess.Revision(g.accessPath)
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.ReadFile("../../web/workbench/rootwell-demo-certificate.pem")
	if err != nil {
		t.Fatal(err)
	}
	catalog := &publicinventory.Catalog{}
	records, err := catalog.Add(input, "", "")
	if err != nil || len(records) != 1 {
		t.Fatal("public fixture unavailable", err)
	}
	for _, mode := range []string{"ready", "anonymous", "setup", "expired", "different revision", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			g.now = time.Now
			w := httptest.NewRecorder()
			if err := g.issueSession(w, mode == "setup", revision, nil, nil); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "/api/certificates/save", nil)
			if mode != "anonymous" {
				r.AddCookie(sessionCookie(t, w))
			}
			original := session{revision: revision}
			if mode == "expired" {
				g.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
			}
			if mode == "different revision" {
				original.revision[0] ^= 1
			}
			if mode == "canceled" {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			out := httptest.NewRecorder()
			g.publishCertificateSave(out, r, original, records[0], 2)
			if mode == "ready" {
				if out.Code != 201 || !strings.Contains(out.Body.String(), records[0].Fingerprint) {
					t.Fatal("valid save confirmation refused")
				}
			} else {
				if out.Code != 503 || !strings.Contains(out.Body.String(), "outcome uncertain") || strings.Contains(out.Body.String(), records[0].Fingerprint) {
					t.Fatal("lost publication authority falsely confirmed or classified as no write")
				}
			}
		})
	}
}
