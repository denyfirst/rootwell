package main

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

//go:embed auth/*
var authAssets embed.FS

const cookieName = "__Host-rootwell_session"

type session struct {
	setup    bool
	expires  time.Time
	revision [32]byte
}

type gate struct {
	accessPath string
	assets     *os.Root
	host       string
	now        func() time.Time
	derive     chan struct{}
	mu         sync.Mutex
	sessions   map[[32]byte]session
	attempts   []time.Time
}

func newGate(accessPath, assetsDir, host string) (*gate, error) {
	root, err := os.OpenRoot(assetsDir)
	if err != nil {
		return nil, errors.New("workbench assets directory could not be opened")
	}
	for _, name := range []string{"index.html", "app.js", "style.css", "theme.js", "wasm-loader.js", "wasm_exec.js", "rootwell.wasm"} {
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			_ = root.Close()
			return nil, errors.New("workbench assets are incomplete; build the browser engine first")
		}
	}
	return &gate{accessPath: accessPath, assets: root, host: host, now: time.Now,
		derive: make(chan struct{}, 1), sessions: make(map[[32]byte]session)}, nil
}

func (g *gate) Close() error { return g.assets.Close() }

func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), display-capture=(), geolocation=(), microphone=(), payment=(), usb=()")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self' 'wasm-unsafe-eval'; img-src 'self'; connect-src 'self'; font-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	if r.Host != g.host || (r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost && r.Method != http.MethodDelete) {
		http.Error(w, "request refused", http.StatusBadRequest)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "query strings are not accepted", http.StatusBadRequest)
		return
	}
	s, signedIn := g.currentSession(r)
	switch r.URL.Path {
	case "/auth.css":
		g.authAsset(w, r, "auth/auth.css", "text/css; charset=utf-8")
		return
	case "/auth.js":
		g.authAsset(w, r, "auth/auth.js", "text/javascript; charset=utf-8")
		return
	case "/login":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w)
			return
		}
		if signedIn {
			if s.setup {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/", http.StatusSeeOther)
			}
			return
		}
		g.authAsset(w, r, "auth/login.html", "text/html; charset=utf-8")
		return
	case "/api/session":
		g.sessionEndpoint(w, r, signedIn)
		return
	case "/api/password":
		g.passwordEndpoint(w, r, s, signedIn)
		return
	case "/setup":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w)
			return
		}
		if !signedIn {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !s.setup {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		g.authAsset(w, r, "auth/setup.html", "text/html; charset=utf-8")
		return
	case "/account":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w)
			return
		}
		if !signedIn {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if s.setup {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		g.authAsset(w, r, "auth/account.html", "text/html; charset=utf-8")
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
	if s.setup {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	g.workbenchAsset(w, r)
}

func (g *gate) currentSession(r *http.Request) (session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil || len(c.Value) != 43 {
		return session{}, false
	}
	id := sha256.Sum256([]byte(c.Value))
	revision, revisionErr := instanceaccess.Revision(g.accessPath)
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[id]
	if !ok || revisionErr != nil || s.revision != revision || !g.now().Before(s.expires) {
		delete(g.sessions, id)
		return session{}, false
	}
	return s, true
}

func (g *gate) sameOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == "http://"+g.host && r.Header.Get("X-Rootwell-Request") == "1" &&
		r.Header.Get("Sec-Fetch-Site") != "cross-site"
}

func (g *gate) allowAttempt() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	keep := g.attempts[:0]
	for _, at := range g.attempts {
		if now.Sub(at) < time.Minute {
			keep = append(keep, at)
		}
	}
	g.attempts = keep
	if len(g.attempts) >= 5 {
		return false
	}
	g.attempts = append(g.attempts, now)
	return true
}

func (g *gate) startDerivation() bool {
	select {
	case g.derive <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *gate) issueSession(w http.ResponseWriter, setup bool, revision [32]byte) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return errors.New("session could not be created")
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	id := sha256.Sum256([]byte(token))
	lifetime := 12 * time.Hour
	if setup {
		lifetime = 15 * time.Minute
	}
	g.mu.Lock()
	for len(g.sessions) >= 32 {
		var oldest [32]byte
		var earliest time.Time
		for key, value := range g.sessions {
			if earliest.IsZero() || value.expires.Before(earliest) {
				oldest, earliest = key, value.expires
			}
		}
		delete(g.sessions, oldest)
	}
	g.sessions[id] = session{setup: setup, expires: g.now().Add(lifetime), revision: revision}
	g.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", MaxAge: int(lifetime / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	return nil
}

func (g *gate) revokeAll(w http.ResponseWriter) {
	g.mu.Lock()
	g.sessions = make(map[[32]byte]session)
	g.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func (g *gate) revokeSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		id := sha256.Sum256([]byte(c.Value))
		g.mu.Lock()
		delete(g.sessions, id)
		g.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

type passwordInput struct {
	Password string `json:"password"`
	Next     string `json:"next,omitempty"`
}

func readPasswordInput(w http.ResponseWriter, r *http.Request) (passwordInput, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return passwordInput{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	var body passwordInput
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF || body.Password == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return passwordInput{}, false
	}
	return body, true
}

func (g *gate) sessionEndpoint(w http.ResponseWriter, r *http.Request, signedIn bool) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	if !g.sameOrigin(r) {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodDelete {
		g.revokeSession(w, r)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if signedIn {
		http.Error(w, "sign out first", http.StatusConflict)
		return
	}
	if !g.allowAttempt() {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	body, ok := readPasswordInput(w, r)
	if !ok || body.Next != "" {
		if ok {
			http.Error(w, "invalid request body", http.StatusBadRequest)
		}
		return
	}
	if !g.startDerivation() {
		http.Error(w, "another check is running", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-g.derive }()
	revisionBefore, err := instanceaccess.Revision(g.accessPath)
	if err != nil {
		http.Error(w, "installation unavailable", http.StatusServiceUnavailable)
		return
	}
	setup, err := instanceaccess.Authenticate(g.accessPath, body.Password)
	if err != nil {
		if errors.Is(err, instanceaccess.ErrWrongPassword) {
			http.Error(w, "password not accepted", http.StatusUnauthorized)
		} else {
			http.Error(w, "installation unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	revisionAfter, err := instanceaccess.Revision(g.accessPath)
	if err != nil || revisionBefore != revisionAfter {
		http.Error(w, "installation changed during sign-in", http.StatusServiceUnavailable)
		return
	}
	if err := g.issueSession(w, setup, revisionAfter); err != nil {
		http.Error(w, "session unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if setup {
		_, _ = io.WriteString(w, `{"mode":"setup"}`)
	} else {
		_, _ = io.WriteString(w, `{"mode":"ready"}`)
	}
}

func (g *gate) passwordEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !g.sameOrigin(r) {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	if !signedIn {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if !g.allowAttempt() {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	body, ok := readPasswordInput(w, r)
	if !ok {
		return
	}
	if !g.startDerivation() {
		http.Error(w, "another check is running", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-g.derive }()
	var err error
	if s.setup {
		err = instanceaccess.ChangeInitialPassword(g.accessPath, body.Password, body.Next)
	} else {
		err = instanceaccess.ChangePassword(g.accessPath, body.Password, body.Next)
	}
	if err != nil {
		if errors.Is(err, instanceaccess.ErrWrongPassword) {
			http.Error(w, "current password not accepted", http.StatusUnauthorized)
		} else if errors.Is(err, instanceaccess.ErrWeakPassword) ||
			errors.Is(err, instanceaccess.ErrPasswordTooLong) ||
			errors.Is(err, instanceaccess.ErrPasswordUnchanged) {
			http.Error(w, "choose a different password between 15 characters and 1024 bytes", http.StatusBadRequest)
		} else {
			http.Error(w, "password change was not saved", http.StatusConflict)
		}
		return
	}
	g.revokeAll(w)
	w.WriteHeader(http.StatusNoContent)
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
	"/": "index.html", "/index.html": "index.html", "/app.js": "app.js",
	"/style.css": "style.css", "/theme.js": "theme.js", "/wasm-loader.js": "wasm-loader.js",
	"/wasm_exec.js": "wasm_exec.js", "/rootwell.wasm": "rootwell.wasm",
	"/favicon.svg": "favicon.svg", "/rootwell-demo-bundle.pem": "rootwell-demo-bundle.pem",
	"/rootwell-demo-certificate.pem":         "rootwell-demo-certificate.pem",
	"/rootwell-verify-demo-ca-files.pem":     "rootwell-verify-demo-ca-files.pem",
	"/rootwell-verify-demo-intermediate.pem": "rootwell-verify-demo-intermediate.pem",
	"/rootwell-verify-demo-leaf.pem":         "rootwell-verify-demo-leaf.pem",
	"/rootwell-verify-demo-root.pem":         "rootwell-verify-demo-root.pem",
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
	http.ServeContent(w, r, name, info.ModTime(), f)
}

func methodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
