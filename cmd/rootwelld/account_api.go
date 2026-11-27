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
		// No session is an answer, not a failure: the sign-in page asks on
		// every visit, and a refusal would read as an error in the browser.
		_, s, ok := g.currentSession(r, false)
		if !ok {
			writeJSON(w, http.StatusOK, map[string]any{"stage": "none"})
			return
		}
		out := map[string]any{"stage": map[stage]string{stageSetup: "setup", stageCode: "code", stageReady: "ready"}[s.stage]}
		if s.stage == stageReady || s.stage == stageCode {
			a, err := g.accounts.Get(s.name)
			if err != nil {
				http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
				return
			}
			// Whether a passkey may stand in for the phone code.
			_, named := passkeyName(r.Host)
			out["passkeys"] = named && len(a.Passkeys) > 0
			if s.stage == stageReady {
				out["name"], out["recovery_left"], out["fresh"] = a.Name, a.RecoveryLeft, s.isFresh(g.now())
			}
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
	keys := g.limitsFor(r, name, valid)
	if wait := g.try(keys...); wait > 0 {
		tooMany(w, wait)
		return
	}
	if !valid || in.Password == "" || len(in.Password) > account.MaxPasswordBytes {
		http.Error(w, "That name and password do not match.", http.StatusUnauthorized)
		return
	}
	if !g.slot(r) {
		g.refund(keys...)
		http.Error(w, "Another sign-in is being checked. Try again.", http.StatusServiceUnavailable)
		return
	}
	defer g.release()
	a, err := g.accounts.CheckPassword(name, in.Password)
	if errors.Is(err, accountstore.ErrRefused) {
		http.Error(w, "That name and password do not match.", http.StatusUnauthorized)
		return
	}
	g.refund(keys...)
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
	keys := g.limitsFor(r, s.name, true)
	wait, live := g.tryCode(id, keys...)
	if !live {
		http.Error(w, "Too many wrong codes. Sign in again.", http.StatusUnauthorized)
		return
	}
	if wait > 0 {
		tooMany(w, wait)
		return
	}
	a, err := g.accounts.UseCode(s.name, s.revision, in.value())
	switch {
	case errors.Is(err, accountstore.ErrRefused):
		if g.spent(w, id) {
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
		g.refundCode(id, keys...)
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	// A session that wrong codes sent together ended meanwhile stays ended,
	// even though this code was right.
	if err := g.promote(w, id, session{stage: stageReady, name: s.name, revision: a.Revision, fresh: g.now().Add(freshLife)}); err != nil {
		http.Error(w, "Sign in again.", http.StatusUnauthorized)
		return
	}
	g.refund(keys...)
	g.succeed(nameLimit(s.name))
	g.signedIn(w, r, s.name, a.Revision)
	codeAccepted(w, in.value(), a)
}

// codeAccepted answers a right code: nothing after a phone code, and after a
// recovery code how many are left, so the page can say so before they run
// out.
func codeAccepted(w http.ResponseWriter, code string, a accountstore.Account) {
	if accountstore.PhoneCode(code) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"recovery_left": a.RecoveryLeft})
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
	// The setup code is 120 random bits: wrong guesses count against their
	// source alone, never against the whole installation, so nobody can keep
	// the owner from setting up or recovering.
	name, valid := accountstore.Name(in.Name)
	if !valid {
		http.Error(w, "Choose a name of letters and digits; dots, dashes and underscores may follow. Up to 64.", http.StatusBadRequest)
		return
	}
	if account.CheckNewPassword(in.Password) != nil {
		http.Error(w, "Choose a password of at least 15 characters that is not a common one.", http.StatusBadRequest)
		return
	}
	keys := []limitKey{sourceLimit(r)}
	if wait := g.try(keys...); wait > 0 {
		tooMany(w, wait)
		return
	}
	code := strings.TrimSpace(in.Code)
	switch err := g.accounts.CheckSetup(code, name); {
	case errors.Is(err, accountstore.ErrRefused):
		http.Error(w, "That setup code does not work for this name. Make a new one on the server with rootwelld setup-code.", http.StatusUnauthorized)
		return
	case err != nil:
		g.refund(keys...)
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	g.refund(keys...)
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
	wait, live := g.tryCode(id, keys...)
	if !live {
		http.Error(w, "Too many wrong codes. Start the setup again.", http.StatusUnauthorized)
		return
	}
	if wait > 0 {
		tooMany(w, wait)
		return
	}
	step, matched := account.CheckCode(s.seed, in.value(), g.now(), -1)
	if !matched {
		if g.spent(w, id) {
			http.Error(w, "Too many wrong codes. Start the setup again.", http.StatusUnauthorized)
			return
		}
		http.Error(w, "That code does not match. Check the phone's clock, then enter the code it shows now.", http.StatusUnauthorized)
		return
	}
	g.refund(keys...)
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
	g.signedIn(w, r, s.name, a.Revision)
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
	keys := g.limitsFor(r, s.name, true)
	wait, live := g.tryCode(id, keys...)
	if !live {
		http.Error(w, "Signed out after five wrong codes.", http.StatusUnauthorized)
		return
	}
	if wait > 0 {
		tooMany(w, wait)
		return
	}
	a, err := g.accounts.UseCode(s.name, s.revision, in.value())
	switch {
	case errors.Is(err, accountstore.ErrRefused):
		if g.spent(w, id) {
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
		g.refundCode(id, keys...)
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := g.promote(w, id, g.withFreshCode(s)); err != nil {
		http.Error(w, "Sign in again.", http.StatusUnauthorized)
		return
	}
	g.refund(keys...)
	g.succeed(nameLimit(s.name))
	codeAccepted(w, in.value(), a)
}

// withFreshCode is s once it showed a fresh code: ten minutes without being
// asked again. The caller moves it to a new token with promote, so a copy of
// the old token, taken earlier, gains nothing from the code.
func (g *gate) withFreshCode(s session) session {
	s.fresh, s.wrong = g.now().Add(freshLife), 0
	s.challenge, s.challengeFor = nil, ""
	return s
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
	keys := g.limitsFor(r, s.name, true)
	if wait := g.try(keys...); wait > 0 {
		tooMany(w, wait)
		return
	}
	if in.Password == "" || len(in.Password) > account.MaxPasswordBytes {
		http.Error(w, "The current password does not match.", http.StatusUnauthorized)
		return
	}
	if !g.slot(r) {
		g.refund(keys...)
		http.Error(w, "Another sign-in is being checked. Try again.", http.StatusServiceUnavailable)
		return
	}
	defer g.release()
	switch _, err := g.accounts.ChangePassword(s.name, s.revision, in.Password, in.Next); {
	case errors.Is(err, accountstore.ErrRefused):
		http.Error(w, "The current password does not match.", http.StatusUnauthorized)
		return
	case errors.Is(err, accountstore.ErrWeak):
		g.refund(keys...)
		http.Error(w, "Choose a different password: at least 15 characters, not a common one, and not the one you have now.", http.StatusBadRequest)
		return
	case errors.Is(err, accountstore.ErrChanged):
		g.refund(keys...)
		g.end(w, id)
		http.Error(w, "The account changed. Sign in again.", http.StatusConflict)
		return
	case err != nil:
		g.refund(keys...)
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	g.refund(keys...)
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
	if _, live := g.tryCode(id); !live {
		http.Error(w, "Signed out after five wrong codes.", http.StatusUnauthorized)
		return
	}
	step, matched := account.CheckCode(s.seed, in.value(), g.now(), -1)
	if !matched {
		if g.spent(w, id) {
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
