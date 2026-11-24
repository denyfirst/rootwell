package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// softPasskey is an ES256 passkey in software, answering as an authenticator
// does for one site.
type softPasskey struct {
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
}

func newSoftPasskey(t *testing.T) *softPasskey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softPasskey{key: key, id: id}
}

// cbor writes the few CBOR shapes an authenticator sends.
func cbor(major byte, n int) []byte {
	if n < 24 {
		return []byte{major<<5 | byte(n)}
	}
	if n < 256 {
		return []byte{major<<5 | 24, byte(n)}
	}
	return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
}

func cborBytes(b []byte) []byte { return append(cbor(2, len(b)), b...) }
func cborText(s string) []byte  { return append(cbor(3, len(s)), s...) }

func (p *softPasskey) authData(rp string, attested bool) []byte {
	hash := sha256.Sum256([]byte(rp))
	flags := byte(0x01 | 0x04)
	if attested {
		flags |= 0x40
	}
	p.count++
	out := binary.BigEndian.AppendUint32(append(hash[:], flags), p.count)
	if !attested {
		return out
	}
	raw, _ := p.key.PublicKey.Bytes()
	out = append(out, make([]byte, 16)...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(p.id)))
	out = append(out, p.id...)
	key := cbor(5, 5)
	key = append(key, 0x01, 0x02) // kty: EC2
	key = append(key, 0x03, 0x26) // alg: -7
	key = append(key, 0x20, 0x01) // crv: P-256
	key = append(key, 0x21)       // x
	key = append(key, cborBytes(raw[1:33])...)
	key = append(key, 0x22) // y
	key = append(key, cborBytes(raw[33:])...)
	return append(out, key...)
}

func clientData(kind, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

func (p *softPasskey) register(rp, origin, challenge string) map[string]string {
	cd := clientData("webauthn.create", challenge, origin)
	object := append(cbor(5, 3), cborText("fmt")...)
	object = append(object, cborText("none")...)
	object = append(object, cborText("attStmt")...)
	object = append(object, cbor(5, 0)...)
	object = append(object, cborText("authData")...)
	object = append(object, cborBytes(p.authData(rp, true))...)
	return map[string]string{"client_data": b64(cd), "attestation": b64(object), "name": "Laptop"}
}

func (p *softPasskey) assert(rp, origin, challenge string) map[string]string {
	cd := clientData("webauthn.get", challenge, origin)
	data := p.authData(rp, false)
	clientHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(bytes.Clone(data), clientHash[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	return map[string]string{"id": b64(p.id), "client_data": b64(cd), "authenticator_data": b64(data), "signature": b64(sig)}
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func options(t *testing.T, g *gate, route string, c *http.Cookie) map[string]any {
	t.Helper()
	w := call(g, "POST", route, `{}`, c)
	var out map[string]any
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("%s: %d %s", route, w.Code, w.Body)
	}
	return out
}

func TestPasskeysSignInAndStandInForAFreshCode(t *testing.T) {
	g, c, e := readyGate(t)
	other := e.signIn(t)
	p := newSoftPasskey(t)
	const origin = "https://" + localHost

	// Adding a passkey: a fresh code, this site's name, and the account's handle.
	o := options(t, g, "/api/passkeys/options", c)
	if o["rp_id"] != "localhost" || o["user_id"] != b64(g.accounts.UserHandle(testName)) || len(o["exclude"].([]any)) != 0 {
		t.Fatalf("create options: %v", o)
	}
	w := call(g, "POST", "/api/passkeys", asJSON(p.register("localhost", origin, o["challenge"].(string))), c)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"name":"Laptop"`) {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	c = sessionCookie(t, w)
	if status(t, g, other) != nil {
		t.Fatal("another session outlived a new passkey")
	}
	if got := status(t, g, c); got["passkeys"] != true {
		t.Fatalf("status after adding: %v", got)
	}
	// The same registration again names a spent challenge.
	if w := call(g, "POST", "/api/passkeys", asJSON(p.register("localhost", origin, o["challenge"].(string))), c); w.Code != http.StatusConflict {
		t.Fatalf("a second answer to one challenge: %d", w.Code)
	}

	// Signing in: the password, then the passkey in place of the phone code.
	codeStage := e.passwordStep(t, testPassword)
	if got := status(t, g, codeStage); got["stage"] != "code" || got["passkeys"] != true {
		t.Fatalf("code stage: %v", got)
	}
	o = options(t, g, "/api/passkey/options", codeStage)
	if o["rp_id"] != "localhost" || len(o["allow"].([]any)) != 1 || o["allow"].([]any)[0] != b64(p.id) {
		t.Fatalf("sign-in options: %v", o)
	}
	answer := p.assert("localhost", origin, o["challenge"].(string))
	w = call(g, "POST", "/api/passkey", asJSON(answer), codeStage)
	if w.Code != http.StatusNoContent {
		t.Fatalf("passkey sign-in: %d %s", w.Code, w.Body)
	}
	ready := sessionCookie(t, w)
	if got := status(t, g, ready); got["stage"] != "ready" || got["fresh"] != true {
		t.Fatalf("after the passkey: %v", got)
	}
	// The same answer again: its challenge is spent.
	again := e.passwordStep(t, testPassword)
	if w := call(g, "POST", "/api/passkey", asJSON(answer), again); w.Code != http.StatusConflict {
		t.Fatalf("a replayed answer: %d", w.Code)
	}
	// A challenge made to add a passkey cannot sign.
	o = options(t, g, "/api/passkeys/options", ready)
	if w := call(g, "POST", "/api/passkey", asJSON(p.assert("localhost", origin, o["challenge"].(string))), ready); w.Code != http.StatusConflict {
		t.Fatalf("a registration challenge used to sign: %d", w.Code)
	}

	// A passkey stands in for a fresh code too.
	e.clock.add(freshLife)
	if w := call(g, "POST", "/api/recovery-codes", `{}`, ready); w.Code != http.StatusPreconditionRequired {
		t.Fatalf("without a fresh code: %d", w.Code)
	}
	o = options(t, g, "/api/passkey/options", ready)
	genuine := p.assert("localhost", origin, o["challenge"].(string))
	forged := map[string]string{}
	for k, v := range genuine {
		forged[k] = v
	}
	forged["signature"] = b64([]byte("not a signature"))
	if w := call(g, "POST", "/api/passkey", asJSON(forged), ready); w.Code != http.StatusUnauthorized {
		t.Fatalf("a forged signature: %d", w.Code)
	}
	// Each challenge takes one answer in its own session: the genuine answer
	// after the forged one finds it spent.
	if w := call(g, "POST", "/api/passkey", asJSON(genuine), ready); w.Code != http.StatusConflict {
		t.Fatalf("a second answer to one challenge in the same session: %d", w.Code)
	}
	o = options(t, g, "/api/passkey/options", ready)
	if w := call(g, "POST", "/api/passkey", asJSON(p.assert("localhost", origin, o["challenge"].(string))), ready); w.Code != http.StatusNoContent {
		t.Fatalf("passkey as a fresh code: %d %s", w.Code, w.Body)
	}
	w = call(g, "POST", "/api/recovery-codes", `{}`, ready)
	if w.Code != http.StatusOK {
		t.Fatalf("after the passkey: %d", w.Code)
	}
	ready = sessionCookie(t, w)

	// No passkeys on an IP address.
	r := httptest.NewRequest("POST", "https://127.0.0.1:4180/api/passkey/options", strings.NewReader(`{}`))
	r.Host = "127.0.0.1:4180"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://127.0.0.1:4180")
	r.Header.Set("X-Rootwell-Request", "1")
	r.AddCookie(ready)
	ip := httptest.NewRecorder()
	g.ServeHTTP(ip, r)
	if ip.Code != http.StatusConflict {
		t.Fatalf("passkey options on an IP address: %d", ip.Code)
	}

	// Removing it, with a fresh code; then sign-in offers none.
	w = call(g, "POST", "/api/passkeys/remove", asJSON(map[string]string{"id": b64(p.id)}), ready)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"passkeys":[]`) {
		t.Fatalf("remove: %d %s", w.Code, w.Body)
	}
	ready = sessionCookie(t, w)
	if w := call(g, "POST", "/api/passkey/options", `{}`, ready); w.Code != http.StatusNotFound {
		t.Fatalf("options without a passkey: %d", w.Code)
	}
	e.clock.add(freshLife)
	for _, route := range []string{"/api/passkeys/options", "/api/passkeys", "/api/passkeys/remove"} {
		if w := call(g, "POST", route, `{}`, ready); w.Code != http.StatusPreconditionRequired {
			t.Fatalf("%s without a fresh code: %d", route, w.Code)
		}
	}
}

func TestPasskeyAnswersAreBoundedAndNamed(t *testing.T) {
	for value, want := range map[string]string{"": "Passkey", "  Work laptop ": "Work laptop"} {
		if got, ok := passkeyLabel(value); !ok || got != want {
			t.Fatalf("label %q: %q %v", value, got, ok)
		}
	}
	for _, bad := range []string{strings.Repeat("x", 65), "tab\there", "line\nbreak"} {
		if _, ok := passkeyLabel(bad); ok {
			t.Fatalf("label %q was accepted", bad)
		}
	}
	if _, ok := unb64(base64.RawURLEncoding.EncodeToString(make([]byte, 10)), 9); ok {
		t.Fatal("an over-long field was read")
	}
	if _, ok := unb64("not base64!", 100); ok {
		t.Fatal("a malformed field was read")
	}
	for host, want := range map[string]bool{"localhost:4180": true, "rootwell.lan:4180": true, "127.0.0.1:4180": false, "[::1]:4180": false, "": false} {
		if _, ok := passkeyName(host); ok != want {
			t.Fatalf("passkeyName(%q) = %v", host, ok)
		}
	}
}
