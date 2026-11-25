package main

import (
	"encoding/hex"
	"net/http"
	"time"

	"github.com/denyfirst/rootwell/internal/accountstore"
)

// deviceCookie marks a browser that signed in to an account completely, with
// a code or a passkey after the password, within the last 30 days. The
// account keeps the digest of each such cookie, at most ten; every complete
// sign-in replaces the browser's cookie with a new one, and a password change
// or a setup forgets them all.
//
// A known device's failed sign-ins count against that device alone. Without
// one, they count against the account name and the source address. So people
// guessing at the name, or sharing the owner's address (everyone on the server
// itself shares 127.0.0.1), cannot keep the owner from signing in on a browser
// they used before.
const deviceCookie = "__Host-rootwell_device"

// limitsFor is what a sign-in attempt for name counts against. An invalid
// name counts against its source address only.
func (g *gate) limitsFor(r *http.Request, name string, valid bool) []limitKey {
	if !valid {
		return []limitKey{sourceLimit(r)}
	}
	if digest, ok := cookieDigest(r, deviceCookie); ok && g.accounts.KnownDevice(name, digest) {
		return []limitKey{{"device:" + hex.EncodeToString(digest[:]), nameFailures}}
	}
	return []limitKey{sourceLimit(r), nameLimit(name)}
}

// signedIn gives the browser a new device cookie once account name, at
// revision, signed in completely, and forgets the one it had. If the account
// cannot keep it, the browser simply stays unknown.
func (g *gate) signedIn(w http.ResponseWriter, r *http.Request, name string, revision uint64) {
	token, digest, err := newToken()
	if err != nil {
		return
	}
	old, _ := cookieDigest(r, deviceCookie)
	if g.accounts.RememberDevice(name, revision, digest, old) != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: deviceCookie, Value: token, Path: "/", MaxAge: int(accountstore.DeviceLife / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}
