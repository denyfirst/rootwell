package main

import (
	"embed"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/rootwell/internal/accountstore"
	"github.com/denyfirst/rootwell/internal/certstore"
	"github.com/denyfirst/rootwell/internal/servingstore"
	"github.com/denyfirst/rootwell/internal/vault"
)

//go:embed auth/*
var authAssets embed.FS

// servePort is the one port Rootwell serves on, on every name.
const servePort = "4180"

type gate struct {
	assets       *os.Root
	hosts        map[string]bool
	loopback     map[string]bool
	authority    []byte
	now          func() time.Time
	derive       chan struct{}
	mu           sync.Mutex
	sessions     map[[32]byte]*session
	failures     map[string]*failures
	crowded      time.Time
	accounts     *accountstore.Store
	certificates *certstore.Store
	vault        *vault.Store
	backups      chan struct{}
	closed       bool
	websiteCheck websiteCheck
	websiteBusy  bool
	websiteLast  time.Time
}

// newGate serves the pages for the accounts and certificates in v, over HTTPS
// to the names s was made for.
func newGate(v *vault.Store, assetsDir string, s servingstore.Serving) (*gate, error) {
	root, err := os.OpenRoot(assetsDir)
	if err != nil {
		return nil, errors.New("workbench assets directory could not be opened")
	}
	for _, name := range []string{"certificates.html", "certificates.js", "inspect.html", "inspect.js", "convert.html", "convert.js", "request.html", "request.js", "ui.js", "rootwell.css", "theme.js", "session.js", "fresh.js", "favicon.svg", "private-worker-client.js", "private-key-worker.js", "pfx-worker-client.js", "pfx-worker.js", "csr-worker-client.js", "csr-worker.js", "wasm-loader.js", "wasm_exec.js", "rootwell.wasm"} {
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			_ = root.Close()
			return nil, errors.New("workbench assets are incomplete; build the browser engine first")
		}
	}
	g := &gate{assets: root, hosts: map[string]bool{}, loopback: map[string]bool{}, now: time.Now, derive: make(chan struct{}, 1),
		sessions: make(map[[32]byte]*session), failures: make(map[string]*failures)}
	for host, loopback := range s.Names.Hosts(servePort) {
		g.hosts[host], g.loopback[host] = true, loopback
	}
	if s.Authority != nil {
		g.authority = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Authority.Raw})
	}
	clock := func() time.Time { return g.now() }
	g.accounts = accountstore.New(v, clock)
	g.certificates = certstore.New(v)
	g.vault = v
	g.backups = make(chan struct{}, 1)
	return g, nil
}

func (g *gate) Close() error {
	g.mu.Lock()
	g.closed = true
	clear(g.sessions)
	g.mu.Unlock()
	return g.assets.Close()
}

func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), display-capture=(), geolocation=(), microphone=(), payment=(), usb=()")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self' 'wasm-unsafe-eval'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; frame-src 'none'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	if r.URL.Path == "/private-key-worker.js" || r.URL.Path == "/pfx-worker.js" || r.URL.Path == "/csr-worker.js" || r.URL.Path == "/certificate-pfx-worker.js" {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'")
	}
	// HTTPS only, and only for the names this installation answers to: a
	// rebound DNS name or another port reaches nothing (audit RW-02).
	if r.TLS == nil || !g.hosts[r.Host] || (r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost && r.Method != http.MethodDelete) {
		http.Error(w, "request refused", http.StatusBadRequest)
		return
	}
	if !g.loopback[r.Host] {
		// Not on loopback names: HSTS there would force HTTPS on every other
		// local port of this machine.
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "query strings are not accepted", http.StatusBadRequest)
		return
	}
	switch r.URL.Path {
	// The account's own pieces: each finds and checks its session itself.
	case "/api/session":
		g.sessionEndpoint(w, r)
		return
	case "/api/session/code":
		g.codeEndpoint(w, r)
		return
	case "/api/setup":
		g.setupEndpoint(w, r)
		return
	case "/api/setup/confirm":
		g.setupConfirmEndpoint(w, r)
		return
	case "/api/fresh":
		g.freshEndpoint(w, r)
		return
	case "/api/password":
		g.passwordEndpoint(w, r)
		return
	case "/api/phone":
		g.phoneEndpoint(w, r)
		return
	case "/api/phone/confirm":
		g.phoneConfirmEndpoint(w, r)
		return
	case "/api/recovery-codes":
		g.recoveryCodesEndpoint(w, r)
		return
	case "/api/passkey/options":
		g.passkeyOptionsEndpoint(w, r)
		return
	case "/api/passkey":
		g.passkeyAnswerEndpoint(w, r)
		return
	case "/api/passkeys":
		g.passkeysEndpoint(w, r)
		return
	case "/api/passkeys/options":
		g.passkeyCreateOptionsEndpoint(w, r)
		return
	case "/api/passkeys/remove":
		g.passkeyRemoveEndpoint(w, r)
		return
	case "/api/installation":
		g.installationEndpoint(w, r)
		return
	case "/api/backup":
		g.backupEndpoint(w, r)
		return
	// Public: the look every page shares, so sign-in and setup wear it too.
	case "/schibsted-grotesk.woff2":
		w.Header().Set("Cache-Control", "no-cache")
		g.authAsset(w, r, "auth/schibsted-grotesk.woff2", "font/woff2")
		return
	case "/rootwell.css", "/theme.js", "/favicon.svg":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w)
			return
		}
		g.workbenchAsset(w, r)
		return
	case "/auth.js":
		g.authAsset(w, r, "auth/auth.js", "text/javascript; charset=utf-8")
		return
	case "/qr.js":
		g.authAsset(w, r, "auth/qr.js", "text/javascript; charset=utf-8")
		return
	case "/passkey.js":
		g.authAsset(w, r, "auth/passkey.js", "text/javascript; charset=utf-8")
		return
	case "/rootwell-ca.pem":
		// The local authority's certificate, public: a browser trusts it once,
		// after comparing its fingerprint with the one rootwelld printed.
		g.authorityFile(w, r)
		return
	}
	_, s, ok := g.currentSession(r, true)
	signedIn := ok && s.stage == stageReady
	switch r.URL.Path {
	case "/login", "/setup":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w)
			return
		}
		if signedIn {
			http.Redirect(w, r, "/certificates", http.StatusSeeOther)
			return
		}
		page := "auth/login.html"
		if r.URL.Path == "/setup" {
			page = "auth/setup.html"
		}
		g.authAsset(w, r, page, "text/html; charset=utf-8")
		return
	case "/api/website-check":
		g.websiteCheckEndpoint(w, r, s, signedIn)
		return
	case "/api/inventory":
		g.inventoryEndpoint(w, r, s, signedIn)
		return
	case "/api/certificates/check", "/api/certificates/save", "/api/certificates/download", "/api/certificates/key/check", "/api/certificates/key/save":
		g.certificateEndpoint(w, r, s, signedIn)
		return
	case "/api/inventory/locations":
		g.inventoryLocationEndpoint(w, r, s, signedIn)
		return
	case "/api/inventory/locations/change":
		g.inventoryLocationChangeEndpoint(w, r, s, signedIn)
		return
	case "/api/inventory/owner":
		g.inventoryOwnerEndpoint(w, r, s, signedIn)
		return
	case "/api/inventory/delete":
		g.inventoryDeleteEndpoint(w, r, s, signedIn)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	if !signedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	switch r.URL.Path {
	case "/":
		// Certificates is the home page.
		http.Redirect(w, r, "/certificates", http.StatusSeeOther)
	case "/account":
		g.authAsset(w, r, "auth/account.html", "text/html; charset=utf-8")
	case "/installation":
		g.authAsset(w, r, "auth/installation.html", "text/html; charset=utf-8")
	case "/website-check":
		g.authAsset(w, r, "auth/website-check.html", "text/html; charset=utf-8")
	case "/website-check.js":
		g.authAsset(w, r, "auth/website-check.js", "text/javascript; charset=utf-8")
	case "/certificate-pfx.js":
		// The Certificates page opens a PFX with these, in a worker that has no
		// network access.
		g.authAsset(w, r, "auth/certificate-pfx.js", "text/javascript; charset=utf-8")
	case "/certificate-pfx-worker.js":
		g.authAsset(w, r, "auth/certificate-pfx-worker.js", "text/javascript; charset=utf-8")
	default:
		g.workbenchAsset(w, r)
	}
}

// stillReady says whether the request's session is still the signed-in one s
// was: the same account at the same revision.
func (g *gate) stillReady(r *http.Request, s session) bool {
	_, current, ok := g.currentSession(r, false)
	return ok && current.stage == stageReady && current.name == s.name && current.revision == s.revision
}

func (g *gate) sameOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == "https://"+r.Host && r.Header.Get("X-Rootwell-Request") == "1" &&
		r.Header.Get("Sec-Fetch-Site") != "cross-site"
}

func (g *gate) authorityFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	if len(g.authority) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="rootwell-ca.pem"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(g.authority)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(g.authority)
	}
}

func (g *gate) authAsset(w http.ResponseWriter, r *http.Request, name, contentType string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	body, err := authAssets.ReadFile(name)
	if err != nil {
		http.Error(w, "asset unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

var workbenchFiles = map[string]string{
	"/certificates": "certificates.html", "/certificates.js": "certificates.js",
	"/inspect": "inspect.html", "/inspect.js": "inspect.js",
	"/convert": "convert.html", "/convert.js": "convert.js",
	"/request": "request.html", "/request.js": "request.js",
	"/ui.js": "ui.js", "/rootwell.css": "rootwell.css", "/theme.js": "theme.js",
	"/session.js": "session.js", "/fresh.js": "fresh.js", "/favicon.svg": "favicon.svg",
	"/private-worker-client.js": "private-worker-client.js", "/private-key-worker.js": "private-key-worker.js",
	"/pfx-worker-client.js": "pfx-worker-client.js", "/pfx-worker.js": "pfx-worker.js",
	"/csr-worker-client.js": "csr-worker-client.js", "/csr-worker.js": "csr-worker.js",
	"/wasm-loader.js": "wasm-loader.js", "/wasm_exec.js": "wasm_exec.js", "/rootwell.wasm": "rootwell.wasm",
}

func (g *gate) workbenchAsset(w http.ResponseWriter, r *http.Request) {
	name, ok := workbenchFiles[r.URL.Path]
	if !ok || strings.Contains(r.URL.EscapedPath(), "%") {
		http.NotFound(w, r)
		return
	}
	f, err := g.assets.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(name, ".wasm") {
		w.Header().Set("Content-Type", "application/wasm")
	}
	// The engine is public code of several megabytes: the browser keeps it and
	// asks again with If-Modified-Since, instead of downloading it on every page
	// (audit RW-21). Everything else stays no-store.
	if name == "rootwell.wasm" || name == "wasm_exec.js" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, name, info.ModTime(), f)
}

func methodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
