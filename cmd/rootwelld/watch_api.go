package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/watchstore"
)

type watchInput struct {
	Target string `json:"target"`
}

type watchOutput struct {
	Sites []watchstore.Site `json:"sites"`
}

// watchEndpoint lists the watched websites (GET /api/watch), adds one
// (POST /api/watch/add) and stops watching one (POST /api/watch/remove).
// Adding needs what a check needs: a signed-in session. Stopping silences a
// watch, so it needs a fresh code, as turning off an alert channel does.
func (g *gate) watchEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.URL.Path == "/api/watch" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		if !signedIn {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Rootwell-Request") != "1" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "request origin refused", http.StatusForbidden)
			return
		}
		sites, err := g.watches.List()
		if err != nil {
			http.Error(w, "the watched websites could not be read", http.StatusServiceUnavailable)
			return
		}
		if sites == nil {
			sites = []watchstore.Site{}
		}
		writeJSON(w, http.StatusOK, watchOutput{Sites: sites})
		return
	}
	if !signedIn {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if !g.post(w, r) {
		return
	}
	var input watchInput
	if !readJSON(w, r, &input) {
		return
	}
	target, ok := watchTarget(input.Target)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter a website name or address, with its port if it is not 443."})
		return
	}
	switch r.URL.Path {
	case "/api/watch/add":
		site, err := g.watches.Add(target)
		switch {
		case errors.Is(err, watchstore.ErrWatched):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "This website is watched already."})
		case errors.Is(err, watchstore.ErrFull):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "50 websites are watched already. Stop watching one first."})
		case err != nil:
			http.Error(w, "the watched websites could not be read", http.StatusServiceUnavailable)
		default:
			writeJSON(w, http.StatusCreated, site)
		}
	case "/api/watch/remove":
		if !s.isFresh(g.now()) {
			needFresh(w)
			return
		}
		err := g.watches.Remove(target)
		switch {
		case errors.Is(err, watchstore.ErrNotWatched):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "This website is not watched."})
		case err != nil:
			http.Error(w, "the watched websites could not be read", http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		http.NotFound(w, r)
	}
}

func dayOf(value string) string {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return ""
	}
	return t.UTC().Format("2 Jan 2006")
}

// watchMessage says what changed on a watched website, with a link to check
// it again.
func watchMessage(c watchstore.Change, link func(string) string) (string, string) {
	site := c.Site
	var subject string
	var b strings.Builder
	switch {
	case c.NewCertificate:
		subject = "Rootwell: " + site.Target + " now serves another certificate"
		b.WriteString(site.Target + " now serves " + site.LeafName)
		if end := dayOf(site.NotAfter); end != "" {
			b.WriteString(", until " + end)
		}
		b.WriteString(".")
		if before := dayOf(c.PreviousEnd); before != "" {
			b.WriteString(" The one it served before ended " + before + ".")
		}
		b.WriteString("\n")
		if c.NewProblem && site.Problem != "" {
			b.WriteString("It also has a problem: " + site.Problem + "\n")
		}
	default:
		subject = "Rootwell: " + site.Target + " has a problem"
		problem := site.Problem
		if problem == "" {
			problem = "The check did not pass."
		}
		b.WriteString(problem + "\n")
	}
	if to := link(site.Target); to != "" {
		b.WriteString(to + "\n")
	}
	b.WriteString("\nRootwell checks this website once a day, and writes when it serves another certificate or has a problem.")
	return subject, b.String()
}

// siteLink is the address of Website check for a site, on the first name
// Rootwell answers to that is not loopback; "" when it has none.
func siteLink(host string) func(string) string {
	if host == "" {
		return func(string) string { return "" }
	}
	return func(target string) string { return "https://" + host + "/website-check#" + target }
}
