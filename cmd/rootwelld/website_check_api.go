package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/websitechain"
	"github.com/denyfirst/rootwell/internal/websiteprobe"
)

type websiteCheck func(context.Context, websiteprobe.Target, []*x509.Certificate, func() bool) (websitechain.Report, error)

// websiteGap is the least time between two checks. One check runs at a time.
const websiteGap = 5 * time.Second

func readWebsiteConsent(w http.ResponseWriter, r *http.Request) (websiteprobe.Target, bool) {
	none := websiteprobe.Target{}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return none, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	defer clear(body)
	if err != nil || !utf8.Valid(body) {
		return none, false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return none, false
	}
	seen := map[string]bool{}
	var target string
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return none, false
		}
		seen[name] = true
		switch name {
		case "target":
			if d.Decode(&target) != nil {
				return none, false
			}
		case "confirm":
			var confirmed bool
			if d.Decode(&confirmed) != nil || !confirmed {
				return none, false
			}
		default:
			return none, false
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(seen) != 2 {
		return none, false
	}
	if _, err = d.Token(); err != io.EOF {
		return none, false
	}
	parsed, err := websiteprobe.ParseTarget(target)
	return parsed, err == nil
}

func (g *gate) websiteCheckEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !signedIn {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if !g.sameOrigin(r) {
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	target, valid := readWebsiteConsent(w, r)
	if !valid {
		http.Error(w, "Enter a website name or address, with its port if it is not 443, for example intranet.example.com:8443. Paths, user names and queries are not accepted.", http.StatusBadRequest)
		return
	}
	permit := func() bool {
		ok := g.stillReady(r, s)
		g.mu.Lock()
		closed := g.closed
		g.mu.Unlock()
		return !closed && ok && r.Context().Err() == nil
	}
	if !permit() {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	if g.websiteCheck == nil && !websiteprobe.Available() {
		http.Error(w, websiteprobe.ErrUnavailable.Error(), http.StatusServiceUnavailable)
		return
	}
	g.mu.Lock()
	now := g.now()
	if g.websiteBusy || (!g.websiteLast.IsZero() && now.Sub(g.websiteLast) < websiteGap) {
		g.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(int(websiteGap/time.Second)))
		http.Error(w, "Another check is running or just finished. Try again in a few seconds.", http.StatusTooManyRequests)
		return
	}
	g.websiteBusy, g.websiteLast = true, now
	g.mu.Unlock()
	defer func() { g.mu.Lock(); g.websiteBusy = false; g.mu.Unlock() }()
	check := g.websiteCheck
	if check == nil {
		check = websiteprobe.Probe
	}
	ctx, cancel := context.WithTimeout(r.Context(), websiteprobe.Timeout+time.Second)
	defer cancel()
	result, err := check(ctx, target, g.savedRoots(), permit)
	if !permit() || ctx.Err() != nil {
		http.Error(w, "session or check no longer available", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, websiteFailure(target, err), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(result)
}

// websiteFailure says what went wrong in words a person can act on. It names
// only the checked target and the address Rootwell itself dialed, never text
// from the peer or the resolver.
func websiteFailure(target websiteprobe.Target, err error) string {
	at := "the server"
	var failure *websiteprobe.Failure
	if errors.As(err, &failure) && failure.Address != "" {
		at = failure.Address
	}
	port := strconv.Itoa(target.Port)
	switch {
	case errors.Is(err, websiteprobe.ErrBlocked):
		return "Rootwell does not check its own machine (127.x, ::1), link-local addresses (169.254.x, fe80::), cloud metadata or reserved addresses."
	case errors.Is(err, websiteprobe.ErrNotFound):
		return target.Host + " was not found. Check the spelling. For an internal name, the Rootwell server must use your company's DNS."
	case errors.Is(err, websiteprobe.ErrDNS):
		return "The DNS server did not answer for " + target.Host + ". Try again in a moment."
	case errors.Is(err, websiteprobe.ErrRefused):
		return "Nothing answers on port " + port + " at " + at + ". Check the port, and that the service is running."
	case errors.Is(err, websiteprobe.ErrTimeout):
		return at + " did not answer on port " + port + " in time. A firewall may block Rootwell, or the server is off."
	case errors.Is(err, websiteprobe.ErrNotTLS):
		return at + " answered on port " + port + ", but not with HTTPS. Check the port; HTTPS is usually 443."
	case errors.Is(err, websiteprobe.ErrHandshake):
		return at + " did not finish a secure connection on port " + port + ". It may accept only TLS 1.0 or 1.1, which browsers no longer allow."
	case errors.Is(err, websiteprobe.ErrTrustStore):
		return websiteprobe.ErrTrustStore.Error()
	}
	return "The check did not finish. Try again."
}

// savedRoots are the self-signed certificate authorities found among the
// saved certificates and their bundles: the roots a person chose to keep. A
// check may end at one of them. Nothing a website sends is ever added here.
func (g *gate) savedRoots() []*x509.Certificate {
	if g.certificates == nil {
		return nil
	}
	records, _, err := g.certificates.List()
	if err != nil {
		return nil
	}
	var roots []*x509.Certificate
	seen := map[string]bool{}
	for _, record := range records {
		for _, der := range append(append([][]byte{record.DER}, record.BundleDER...), record.IssuerDER...) {
			if len(roots) == websitechain.MaxSavedRoots {
				return roots
			}
			if seen[string(der)] {
				continue
			}
			seen[string(der)] = true
			c, err := x509.ParseCertificate(der)
			if err == nil && websitechain.SavedRoot(c) {
				roots = append(roots, c)
			}
		}
	}
	return roots
}
