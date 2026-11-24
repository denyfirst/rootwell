package main

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/account"
	"github.com/denyfirst/rootwell/internal/accountstore"
)

// readJSON reads exactly one JSON object with known fields into v.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "response unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
	http.Error(w, "Too many wrong tries. Wait a little, then try again.", http.StatusTooManyRequests)
}

func needFresh(w http.ResponseWriter) {
	http.Error(w, "Enter a code from your phone first.", http.StatusPreconditionRequired)
}

// post checks what every change needs: POST from the page itself.
func (g *gate) post(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return false
	}
	if !g.sameOrigin(r) {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return false
	}
	return true
}

// slot waits up to five seconds for the one password check that may run at
// a time: each takes 64 MiB.
func (g *gate) slot(r *http.Request) bool {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case g.derive <- struct{}{}:
		return true
	case <-timer.C:
	case <-r.Context().Done():
	}
	return false
}

func (g *gate) release() { <-g.derive }

// ready finds a signed-in session, or answers 401.
func (g *gate) ready(w http.ResponseWriter, r *http.Request) ([32]byte, session, bool) {
	id, s, ok := g.currentSession(r, true)
	if !ok || s.stage != stageReady {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return id, session{}, false
	}
	return id, s, true
}

func (s session) isFresh(now time.Time) bool { return now.Before(s.fresh) }

type codeInput struct {
	Code string `json:"code"`
}

func (in codeInput) value() string { return strings.TrimSpace(in.Code) }

// sessionEndpoint: GET tells a page where its session stands, POST checks a
// name and password, DELETE signs out.
func (g *gate) sessionEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_, s, ok := g.currentSession(r, false)
		if !ok {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		out := map[string]any{"stage": map[stage]string{stageSetup: "setup", stageCode: "code", stageReady: "ready"}[s.stage]}
		if s.stage == stageReady {
			a, err := g.accounts.Get(s.name)
			if err != nil {
				http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
				return
			}
			out["name"], out["recovery_left"], out["fresh"] = a.Name, a.RecoveryLeft, s.isFresh(g.now())
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodDelete:
		if !g.sameOrigin(r) {
			http.Error(w, "request origin refused", http.StatusForbidden)
			return
		}
		if id, ok := sessionID(r); ok {
			g.end(w, id)
		} else {
			clearCookie(w)
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPost:
		g.signIn(w, r)
	default:
		methodNotAllowed(w)
	}
}

func (g *gate) signIn(w http.ResponseWriter, r *http.Request) {
	if !g.post(w, r) {
		return
	}
	var in struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	name, valid := accountstore.Name(in.Name)
	keys := []limitKey{sourceLimit(r)}
	if valid {
		keys = append(keys, nameLimit(name))
	}
	if wait := g.wait(keys...); wait > 0 {
		tooMany(w, wait)
		return
	}
	if !valid || in.Password == "" || len(in.Password) > account.MaxPasswordBytes {
		g.fail(keys...)
		http.Error(w, "That name and password do not match.", http.StatusUnauthorized)
		return
	}
	if !g.slot(r) {
		http.Error(w, "Another sign-in is being checked. Try again.", http.StatusServiceUnavailable)
		return
	}
	defer g.release()
	a, err := g.accounts.CheckPassword(name, in.Password)
	if errors.Is(err, accountstore.ErrRefused) {
		g.fail(keys...)
		http.Error(w, "That name and password do not match.", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	old, _ := sessionID(r)
	if err := g.issue(w, old, session{stage: stageCode, name: name, revision: a.Revision}); err != nil {
		http.Error(w, "Too many sign-ins are open. Try again in a few minutes.", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// codeEndpoint takes the phone code, or a recovery code, after the password.
func (g *gate) codeEndpoint(w http.ResponseWriter, r *http.Request) {
	if !g.post(w, r) {
		return
	}
	id, s, ok := g.currentSession(r, false)
	if !ok || s.stage != stageCode {
		http.Error(w, "Sign in again.", http.StatusUnauthorized)
		return
	}
	var in codeInput
	if !readJSON(w, r, &in) {
		return
	}
	keys := []limitKey{sourceLimit(r), nameLimit(s.name)}
	if wait := g.wait(keys...); wait > 0 {
		tooMany(w, wait)
		return
	}
	a, err := g.accounts.UseCode(s.name, s.revision, in.value())
	switch {
	case errors.Is(err, accountstore.ErrRefused):
		g.fail(keys...)
		if g.wrongCode(w, id) {
			http.Error(w, "Too many wrong codes. Sign in again.", http.StatusUnauthorized)
			return
		}
		http.Error(w, "That code does not match.", http.StatusUnauthorized)
		return
	case errors.Is(err, accountstore.ErrChanged):
		g.end(w, id)
		http.Error(w, "The account changed. Sign in again.", http.StatusConflict)
		return
	case err != nil:
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	g.succeed(nameLimit(s.name))
	if err := g.issue(w, id, session{stage: stageReady, name: s.name, revision: a.Revision, fresh: g.now().Add(freshLife)}); err != nil {
		http.Error(w, "Too many sign-ins are open. Try again in a few minutes.", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setupEndpoint takes a setup code, a name and a password, and starts
// confirming a phone. Nothing is saved until the phone is confirmed.
func (g *gate) setupEndpoint(w http.ResponseWriter, r *http.Request) {
	if !g.post(w, r) {
		return
	}
	var in struct {
		Code     string `json:"code"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	keys := []limitKey{sourceLimit(r), {"setup", sourceFailures}}
	if wait := g.wait(keys...); wait > 0 {
		tooMany(w, wait)
		return
	}
	name, valid := accountstore.Name(in.Name)
	if !valid {
		http.Error(w, "Choose a name of letters and digits; dots, dashes and underscores may follow. Up to 64.", http.StatusBadRequest)
		return
	}
	if account.CheckNewPassword(in.Password) != nil {
		http.Error(w, "Choose a password of at least 15 characters that is not a common one.", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(in.Code)
	switch err := g.accounts.CheckSetup(code, name); {
	case errors.Is(err, accountstore.ErrRefused):
		g.fail(keys...)
		http.Error(w, "That setup code does not work for this name. Make a new one on the server with rootwelld setup-code.", http.StatusUnauthorized)
		return
	case err != nil:
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	if !g.slot(r) {
		http.Error(w, "Another sign-in is being checked. Try again.", http.StatusServiceUnavailable)
		return
	}
	hash, err := account.HashPassword(in.Password)
	g.release()
	if err != nil {
		http.Error(w, "Choose a password of at least 15 characters that is not a common one.", http.StatusBadRequest)
		return
	}
	g.startPhone(w, r, session{stage: stageSetup, name: name, setupCode: code, password: hash})
}

// startPhone makes a phone key, keeps it with the session and sends it, with
// its QR code, for the phone to read.
func (g *gate) startPhone(w http.ResponseWriter, r *http.Request, s session) {
	seed, err := account.NewSeed()
	if err != nil {
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	rows, err := account.SeedQR(s.name, seed)
	if err != nil {
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	id, _ := sessionID(r)
	if s.stage == stageSetup {
		s.seed = seed
		if err := g.issue(w, id, s); err != nil {
			http.Error(w, "Too many sign-ins are open. Try again in a few minutes.", http.StatusServiceUnavailable)
			return
		}
	} else if !g.update(id, func(live *session) { live.seed = seed }) {
		http.Error(w, "Sign in again.", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": s.name, "key": seed, "qr": rows})
}

// setupConfirmEndpoint saves the account once its phone shows a right code,
// spends the setup code and signs the person in. The recovery codes are shown
// this once.
func (g *gate) setupConfirmEndpoint(w http.ResponseWriter, r *http.Request) {
	if !g.post(w, r) {
		return
	}
	id, s, ok := g.currentSession(r, false)
	if !ok || s.stage != stageSetup {
		http.Error(w, "Start the setup again.", http.StatusUnauthorized)
		return
	}
	var in codeInput
	if !readJSON(w, r, &in) {
		return
	}
	keys := []limitKey{sourceLimit(r)}
	if wait := g.wait(keys...); wait > 0 {
		tooMany(w, wait)
		return
	}
	step, matched := account.CheckCode(s.seed, in.value(), g.now(), -1)
	if !matched {
		g.fail(keys...)
		if g.wrongCode(w, id) {
			http.Error(w, "Too many wrong codes. Start the setup again.", http.StatusUnauthorized)
			return
		}
		http.Error(w, "That code does not match. Check the phone's clock, then enter the code it shows now.", http.StatusUnauthorized)
		return
	}
	codes, a, err := g.accounts.FinishSetup(s.setupCode, s.name, s.password, s.seed, step)
	switch {
	case errors.Is(err, accountstore.ErrRefused):
		g.end(w, id)
		http.Error(w, "That setup code no longer works. Make a new one on the server with rootwelld setup-code.", http.StatusConflict)
		return
	case err != nil:
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	// A setup for an existing account replaces how it signs in: its other
	// sessions end.
	g.endAccount(s.name)
	if err := g.issue(w, id, session{stage: stageReady, name: s.name, revision: a.Revision, fresh: g.now().Add(freshLife)}); err != nil {
		http.Error(w, "The account is ready. Sign in.", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// freshEndpoint takes a phone code, or a recovery code, so that the next ten
// minutes need no other.
func (g *gate) freshEndpoint(w http.ResponseWriter, r *http.Request) {
	if !g.post(w, r) {
		return
	}
	id, s, ok := g.ready(w, r)
	if !ok {
		return
	}
	var in codeInput
	if !readJSON(w, r, &in) {
		return
	}
	keys := []limitKey{sourceLimit(r), nameLimit(s.name)}
	if wait := g.wait(keys...); wait > 0 {
		tooMany(w, wait)
		return
	}
	switch _, err := g.accounts.UseCode(s.name, s.revision, in.value()); {
	case errors.Is(err, accountstore.ErrRefused):
		g.fail(keys...)
		if g.wrongCode(w, id) {
			http.Error(w, "Signed out after five wrong codes.", http.StatusUnauthorized)
			return
		}
		http.Error(w, "That code does not match.", http.StatusUnauthorized)
		return
	case errors.Is(err, accountstore.ErrChanged):
		g.end(w, id)
		http.Error(w, "The account changed. Sign in again.", http.StatusConflict)
		return
	case err != nil:
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	g.succeed(nameLimit(s.name))
	now := g.now()
	g.update(id, func(live *session) { live.fresh, live.wrong = now.Add(freshLife), 0 })
	w.WriteHeader(http.StatusNoContent)
}

// passwordEndpoint changes the password. Every session ends, this one too.
func (g *gate) passwordEndpoint(w http.ResponseWriter, r *http.Request) {
	if !g.post(w, r) {
		return
	}
	id, s, ok := g.ready(w, r)
	if !ok {
		return
	}
	if !s.isFresh(g.now()) {
		needFresh(w)
		return
	}
	var in struct {
		Password string `json:"password"`
		Next     string `json:"next"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	keys := []limitKey{sourceLimit(r), nameLimit(s.name)}
	if wait := g.wait(keys...); wait > 0 {
		tooMany(w, wait)
		return
	}
	if in.Password == "" || len(in.Password) > account.MaxPasswordBytes {
		g.fail(keys...)
		http.Error(w, "The current password does not match.", http.StatusUnauthorized)
		return
	}
	if !g.slot(r) {
		http.Error(w, "Another sign-in is being checked. Try again.", http.StatusServiceUnavailable)
		return
	}
	defer g.release()
	switch _, err := g.accounts.ChangePassword(s.name, s.revision, in.Password, in.Next); {
	case errors.Is(err, accountstore.ErrRefused):
		g.fail(keys...)
		http.Error(w, "The current password does not match.", http.StatusUnauthorized)
		return
	case errors.Is(err, accountstore.ErrWeak):
		http.Error(w, "Choose a different password: at least 15 characters, not a common one, and not the one you have now.", http.StatusBadRequest)
		return
	case errors.Is(err, accountstore.ErrChanged):
		g.end(w, id)
		http.Error(w, "The account changed. Sign in again.", http.StatusConflict)
		return
	case err != nil:
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	g.endAccount(s.name)
	clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// phoneEndpoint starts replacing the phone; phoneConfirmEndpoint finishes it
// once the new phone shows a right code.
func (g *gate) phoneEndpoint(w http.ResponseWriter, r *http.Request) {
	if !g.post(w, r) {
		return
	}
	_, s, ok := g.ready(w, r)
	if !ok {
		return
	}
	if !s.isFresh(g.now()) {
		needFresh(w)
		return
	}
	var in struct{}
	if !readJSON(w, r, &in) {
		return
	}
	g.startPhone(w, r, s)
}

func (g *gate) phoneConfirmEndpoint(w http.ResponseWriter, r *http.Request) {
	if !g.post(w, r) {
		return
	}
	id, s, ok := g.ready(w, r)
	if !ok {
		return
	}
	if !s.isFresh(g.now()) {
		needFresh(w)
		return
	}
	if s.seed == "" {
		http.Error(w, "Start again: show the new key first.", http.StatusConflict)
		return
	}
	var in codeInput
	if !readJSON(w, r, &in) {
		return
	}
	step, matched := account.CheckCode(s.seed, in.value(), g.now(), -1)
	if !matched {
		if g.wrongCode(w, id) {
			http.Error(w, "Signed out after five wrong codes.", http.StatusUnauthorized)
			return
		}
		http.Error(w, "That code does not match. Check the phone's clock, then enter the code it shows now.", http.StatusUnauthorized)
		return
	}
	a, err := g.accounts.ReplacePhone(s.name, s.revision, s.seed, step)
	if !g.changed(w, id, s, err) {
		return
	}
	if err := g.issue(w, id, session{stage: stageReady, name: s.name, revision: a.Revision, fresh: s.fresh}); err != nil {
		http.Error(w, "The phone is replaced. Sign in again.", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// recoveryCodesEndpoint replaces every recovery code with ten new ones, shown
// this once.
func (g *gate) recoveryCodesEndpoint(w http.ResponseWriter, r *http.Request) {
	if !g.post(w, r) {
		return
	}
	id, s, ok := g.ready(w, r)
	if !ok {
		return
	}
	if !s.isFresh(g.now()) {
		needFresh(w)
		return
	}
	var in struct{}
	if !readJSON(w, r, &in) {
		return
	}
	codes, a, err := g.accounts.NewRecoveryCodes(s.name, s.revision)
	if !g.changed(w, id, s, err) {
		return
	}
	if err := g.issue(w, id, session{stage: stageReady, name: s.name, revision: a.Revision, fresh: s.fresh}); err != nil {
		http.Error(w, "The codes are replaced. Sign in again.", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// changed answers a change's error; on success it ends the account's other
// sessions, since how it signs in changed.
func (g *gate) changed(w http.ResponseWriter, id [32]byte, s session, err error) bool {
	switch {
	case errors.Is(err, accountstore.ErrChanged):
		g.end(w, id)
		http.Error(w, "The account changed. Sign in again.", http.StatusConflict)
		return false
	case err != nil:
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return false
	}
	g.endAccount(s.name)
	return true
}
