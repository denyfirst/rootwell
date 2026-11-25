package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/accountstore"
	"github.com/denyfirst/rootwell/internal/passkey"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// unb64 reads a base64url field of at most limit bytes.
func unb64(value string, limit int) ([]byte, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return b, err == nil && len(b) > 0 && len(b) <= limit
}

const (
	purposeSignIn   = "sign-in"
	purposeFresh    = "fresh"
	purposeRegister = "register"
)

func noPasskeysHere(w http.ResponseWriter) {
	http.Error(w, "Passkeys work on a name, such as localhost, not on an IP address.", http.StatusConflict)
}

// newChallenge keeps a fresh challenge with the session, for purpose.
func (g *gate) newChallenge(w http.ResponseWriter, id [32]byte, purpose string) ([]byte, bool) {
	challenge, err := passkey.NewChallenge()
	if err != nil {
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return nil, false
	}
	until := g.now().Add(passkeyLife)
	if !g.update(id, func(live *session) {
		live.challenge, live.challengeFor, live.challengeUntil = challenge, purpose, until
	}) {
		http.Error(w, "Sign in again.", http.StatusUnauthorized)
		return nil, false
	}
	return challenge, true
}

// takeChallenge hands out the session's challenge once, if it is still good
// and was made for purpose.
func (g *gate) takeChallenge(id [32]byte, purpose string) []byte {
	var out []byte
	now := g.now()
	g.update(id, func(live *session) {
		if live.challengeFor == purpose && now.Before(live.challengeUntil) {
			out = live.challenge
		}
		live.challenge, live.challengeFor, live.challengeUntil = nil, "", now
	})
	return out
}

// passkeyOptionsEndpoint sends what the browser needs to ask a passkey to
// sign: after the password, in place of a phone code; when signed in, in
// place of a fresh code.
func (g *gate) passkeyOptionsEndpoint(w http.ResponseWriter, r *http.Request) {
	if !g.post(w, r) {
		return
	}
	id, s, ok := g.currentSession(r, false)
	if !ok || (s.stage != stageCode && s.stage != stageReady) {
		http.Error(w, "Sign in again.", http.StatusUnauthorized)
		return
	}
	var in struct{}
	if !readJSON(w, r, &in) {
		return
	}
	rp, ok := passkeyName(r.Host)
	if !ok {
		noPasskeysHere(w)
		return
	}
	ids, err := g.accounts.PasskeyCredentials(s.name)
	if err != nil {
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	if len(ids) == 0 {
		http.Error(w, "This account has no passkey yet.", http.StatusNotFound)
		return
	}
	purpose := purposeFresh
	if s.stage == stageCode {
		purpose = purposeSignIn
	}
	challenge, ok := g.newChallenge(w, id, purpose)
	if !ok {
		return
	}
	allow := make([]string, len(ids))
	for i, credential := range ids {
		allow[i] = b64(credential)
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": b64(challenge), "rp_id": rp, "allow": allow, "timeout": passkeyLife.Milliseconds()})
}

// passkeyAnswerEndpoint takes a passkey's signature: it signs in after the
// password, or counts as a fresh code when signed in.
func (g *gate) passkeyAnswerEndpoint(w http.ResponseWriter, r *http.Request) {
	if !g.post(w, r) {
		return
	}
	id, s, ok := g.currentSession(r, false)
	if !ok || (s.stage != stageCode && s.stage != stageReady) {
		http.Error(w, "Sign in again.", http.StatusUnauthorized)
		return
	}
	var in struct {
		ID                string `json:"id"`
		ClientData        string `json:"client_data"`
		AuthenticatorData string `json:"authenticator_data"`
		Signature         string `json:"signature"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	keys := g.limitsFor(r, s.name, true)
	wait, live := g.tryCode(id, keys...)
	if !live {
		http.Error(w, "Too many wrong answers. Sign in again.", http.StatusUnauthorized)
		return
	}
	if wait > 0 {
		tooMany(w, wait)
		return
	}
	purpose := purposeFresh
	if s.stage == stageCode {
		purpose = purposeSignIn
	}
	challenge := g.takeChallenge(id, purpose)
	rp, rpOK := passkeyName(r.Host)
	credential, okID := unb64(in.ID, 1023)
	clientData, okCD := unb64(in.ClientData, 4096)
	authenticatorData, okAD := unb64(in.AuthenticatorData, 1024)
	signature, okSig := unb64(in.Signature, 1024)
	if challenge == nil || !rpOK {
		g.refundCode(id, keys...)
		http.Error(w, "Start again: ask the passkey once more.", http.StatusConflict)
		return
	}
	var a accountstore.Account
	err := passkey.ErrRefused
	if okID && okCD && okAD && okSig {
		a, err = g.accounts.UsePasskey(s.name, s.revision, credential, func(c passkey.Credential) (uint32, error) {
			return passkey.VerifyAssertion(rp, "https://"+r.Host, challenge, c, clientData, authenticatorData, signature)
		})
	}
	switch {
	case errors.Is(err, accountstore.ErrRefused), errors.Is(err, passkey.ErrRefused):
		if g.spent(w, id) {
			http.Error(w, "Too many wrong answers. Sign in again.", http.StatusUnauthorized)
			return
		}
		http.Error(w, "That passkey was not accepted.", http.StatusUnauthorized)
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
	next := g.withFreshCode(s)
	if s.stage == stageCode {
		next = session{stage: stageReady, name: s.name, revision: a.Revision, fresh: next.fresh}
	}
	if err := g.promote(w, id, next); err != nil {
		http.Error(w, "Sign in again.", http.StatusUnauthorized)
		return
	}
	g.refund(keys...)
	g.succeed(nameLimit(s.name))
	if s.stage == stageCode {
		g.signedIn(w, r, s.name, a.Revision)
	}
	w.WriteHeader(http.StatusNoContent)
}

func passkeyList(a accountstore.Account) map[string]any {
	list := make([]map[string]string, 0, len(a.Passkeys))
	for _, p := range a.Passkeys {
		list = append(list, map[string]string{"id": b64(p.ID), "name": p.Name, "added": p.Added, "last_used": p.LastUsed})
	}
	return map[string]any{"passkeys": list}
}

// passkeyLabel is the name a person gives a passkey: up to 64 printable
// characters; "Passkey" when empty.
func passkeyLabel(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Passkey", true
	}
	if utf8.RuneCountInString(value) > 64 {
		return "", false
	}
	for _, c := range value {
		if !unicode.IsPrint(c) {
			return "", false
		}
	}
	return value, true
}

// passkeysEndpoint lists the account's passkeys, and adds one.
func (g *gate) passkeysEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		_, s, ok := g.ready(w, r)
		if !ok {
			return
		}
		a, err := g.accounts.Get(s.name)
		if err != nil {
			http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, passkeyList(a))
		return
	}
	id, s, ok := g.freshChange(w, r)
	if !ok {
		return
	}
	var in struct {
		ClientData  string `json:"client_data"`
		Attestation string `json:"attestation"`
		Name        string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	label, okLabel := passkeyLabel(in.Name)
	challenge := g.takeChallenge(id, purposeRegister)
	rp, rpOK := passkeyName(r.Host)
	clientData, okCD := unb64(in.ClientData, 4096)
	attestation, okAtt := unb64(in.Attestation, 16<<10)
	if !okLabel {
		http.Error(w, "Name the passkey in up to 64 characters.", http.StatusBadRequest)
		return
	}
	if challenge == nil || !rpOK {
		http.Error(w, "Start again: add the passkey once more.", http.StatusConflict)
		return
	}
	if !okCD || !okAtt {
		http.Error(w, "That passkey could not be added.", http.StatusBadRequest)
		return
	}
	credential, err := passkey.VerifyRegistration(rp, "https://"+r.Host, challenge, clientData, attestation)
	if err != nil {
		http.Error(w, "That passkey could not be added. It must ask for your PIN, fingerprint or face.", http.StatusBadRequest)
		return
	}
	a, err := g.accounts.AddPasskey(s.name, s.revision, credential, label)
	if errors.Is(err, accountstore.ErrPasskeyLimit) {
		http.Error(w, "This passkey is added already, or the account has ten.", http.StatusConflict)
		return
	}
	if !g.changed(w, id, s, err) {
		return
	}
	if err := g.issue(w, id, session{stage: stageReady, name: s.name, revision: a.Revision, fresh: s.fresh}); err != nil {
		http.Error(w, "The passkey is added. Sign in again.", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusCreated, passkeyList(a))
}

// freshChange finds a signed-in session with a fresh code, for a change to
// how the account signs in.
func (g *gate) freshChange(w http.ResponseWriter, r *http.Request) ([32]byte, session, bool) {
	if !g.post(w, r) {
		return [32]byte{}, session{}, false
	}
	id, s, ok := g.ready(w, r)
	if !ok {
		return id, s, false
	}
	if !s.isFresh(g.now()) {
		needFresh(w)
		return id, s, false
	}
	return id, s, true
}

// passkeyCreateOptionsEndpoint sends what the browser needs to make a new
// passkey for this account on this name.
func (g *gate) passkeyCreateOptionsEndpoint(w http.ResponseWriter, r *http.Request) {
	id, s, ok := g.freshChange(w, r)
	if !ok {
		return
	}
	var in struct{}
	if !readJSON(w, r, &in) {
		return
	}
	rp, ok := passkeyName(r.Host)
	if !ok {
		noPasskeysHere(w)
		return
	}
	ids, err := g.accounts.PasskeyCredentials(s.name)
	if err != nil {
		http.Error(w, "accounts unavailable", http.StatusServiceUnavailable)
		return
	}
	challenge, ok := g.newChallenge(w, id, purposeRegister)
	if !ok {
		return
	}
	exclude := make([]string, len(ids))
	for i, credential := range ids {
		exclude[i] = b64(credential)
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": b64(challenge), "rp_id": rp, "user_id": b64(g.accounts.UserHandle(s.name)),
		"user_name": s.name, "exclude": exclude, "timeout": passkeyLife.Milliseconds()})
}

// passkeyRemoveEndpoint forgets one passkey.
func (g *gate) passkeyRemoveEndpoint(w http.ResponseWriter, r *http.Request) {
	id, s, ok := g.freshChange(w, r)
	if !ok {
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	credential, okID := unb64(in.ID, 1023)
	if !okID {
		http.Error(w, "That passkey is not on this account.", http.StatusNotFound)
		return
	}
	a, err := g.accounts.RemovePasskey(s.name, s.revision, credential)
	if errors.Is(err, accountstore.ErrRefused) {
		http.Error(w, "That passkey is not on this account.", http.StatusNotFound)
		return
	}
	if !g.changed(w, id, s, err) {
		return
	}
	if err := g.issue(w, id, session{stage: stageReady, name: s.name, revision: a.Revision, fresh: s.fresh}); err != nil {
		http.Error(w, "The passkey is removed. Sign in again.", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, passkeyList(a))
}
