package acmestaging

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"golang.org/x/crypto/acme"
)

const nonceURL = "https://" + host + "/acme/new-nonce"
const registerURL = "https://" + host + "/acme/new-acct"

func liveDependencies() dependencies {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
	return dependencies{lookup: net.DefaultResolver.LookupNetIP, dial: dialer.DialContext, tls: &tls.Config{MinVersion: tls.VersionTLS12}}
}

// RegistrationTerms performs only a directory GET; it never fetches/accepts the
// terms or obtains signer authority. The terms URL is a strictly validated link.
func RegistrationTerms(ctx context.Context, permit func() bool) (string, error) {
	if !Available() {
		return "", errRefused
	}
	return registrationTerms(ctx, permit, liveDependencies())
}

func registrationTerms(ctx context.Context, permit func() bool, deps dependencies) (string, error) {
	client, guard, closeTransport := registrationClient(ctx, permit, deps, nil, false)
	defer closeTransport()
	directory, err := client.Discover(guard.ctx)
	if err != nil || !guard.allowed() || !validRegistrationDirectory(directory) {
		return "", errRefused
	}
	return directory.Terms, nil
}

// RegisterAccount and FindAccount are deliberately distinct. Finding uses only
// onlyReturnExisting, never a terms agreement or a creation fallback.
func RegisterAccount(ctx context.Context, permit func() bool, signer crypto.Signer, terms string) (string, bool, error) {
	if !Available() {
		return "", false, errRefused
	}
	return registerAccount(ctx, permit, liveDependencies(), signer, terms, false)
}

func FindAccount(ctx context.Context, permit func() bool, signer crypto.Signer) (string, bool, error) {
	if !Available() {
		return "", false, errRefused
	}
	return registerAccount(ctx, permit, liveDependencies(), signer, "", true)
}

func registerAccount(ctx context.Context, permit func() bool, deps dependencies, signer crypto.Signer, terms string, lookup bool) (string, bool, error) {
	if !validAccountSigner(signer) || (!lookup && !inventorystore.ValidStagingTermsURL(terms)) || (lookup && terms != "") {
		return "", false, errRefused
	}
	client, guard, closeTransport := registrationClient(ctx, permit, deps, signer, lookup)
	defer closeTransport()
	directory, err := client.Discover(guard.ctx)
	if err != nil || !guard.allowed() || !validRegistrationDirectory(directory) || (!lookup && directory.Terms != terms) {
		return "", false, errRefused
	}
	var account *acme.Account
	if lookup {
		account, err = client.GetReg(guard.ctx, "")
	} else {
		account, err = client.Register(guard.ctx, &acme.Account{}, func(value string) bool { return value == terms && guard.allowed() })
	}
	if !guard.allowed() {
		return "", false, errRefused
	}
	if lookup && errors.Is(err, acme.ErrNoAccount) && guard.absent {
		return "", true, nil
	}
	// Register caches a strictly preflighted URI when the key was already known.
	if !lookup && errors.Is(err, acme.ErrAccountAlreadyExists) && validRegistrationAccountURL(string(client.KID)) {
		return string(client.KID), false, nil
	}
	if err != nil || account == nil || account.Status != acme.StatusValid || !validRegistrationAccountURL(account.URI) {
		return "", false, errRefused
	}
	return account.URI, false, nil
}

func validAccountSigner(signer crypto.Signer) bool {
	key, ok := signer.(*ecdsa.PrivateKey)
	if !ok || key == nil || key.Curve != elliptic.P256() {
		return false
	}
	raw, err := key.Bytes()
	defer clear(raw)
	if err != nil || len(raw) != 32 {
		return false
	}
	parsed, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	return err == nil && key.PublicKey.Equal(&parsed.PublicKey)
}

func validRegistrationDirectory(d acme.Directory) bool {
	return d.NonceURL == nonceURL && d.RegURL == registerURL && !d.ExternalAccountRequired && inventorystore.ValidStagingTermsURL(d.Terms)
}

func validRegistrationAccountURL(value string) bool {
	const prefix = "https://" + host + "/acme/acct/"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	number := strings.TrimPrefix(value, prefix)
	if len(number) == 0 || len(number) > 64 || number[0] == '0' {
		return false
	}
	for _, c := range number {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

type registrationTransport struct {
	base                                 http.RoundTripper
	ctx                                  context.Context
	allowed                              func() bool
	signer                               crypto.Signer
	lookup                               bool
	directory, nonceUsed, posted, absent bool
	nonce                                string
}

func registrationClient(parent context.Context, permit func() bool, deps dependencies, signer crypto.Signer, lookup bool) (*acme.Client, *registrationTransport, func()) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	allowed := func() bool { return ctx.Err() == nil && permit != nil && permit() }
	transport := pinnedTransport(ctx, allowed, deps)
	guard := &registrationTransport{base: transport, ctx: ctx, allowed: allowed, signer: signer, lookup: lookup}
	client := &acme.Client{Key: signer, DirectoryURL: acmeplan.Directory, UserAgent: "Rootwell-staging-account",
		HTTPClient:   &http.Client{Transport: guard, CheckRedirect: func(*http.Request, []*http.Request) error { return errRefused }},
		RetryBackoff: func(int, *http.Request, *http.Response) time.Duration { return 0 }}
	return client, guard, func() { cancel(); transport.CloseIdleConnections() }
}

func (t *registrationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.allowed() || r.Host != host || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		return nil, errRefused
	}
	kind := ""
	switch {
	case r.Method == http.MethodGet && r.URL.String() == acmeplan.Directory && r.Body == nil && !t.directory:
		t.directory = true
		kind = "directory"
	case r.Method == http.MethodHead && r.URL.String() == nonceURL && r.Body == nil && t.directory && !t.nonceUsed && t.signer != nil:
		t.nonceUsed = true
		kind = "nonce"
	case r.Method == http.MethodPost && r.URL.String() == registerURL && t.directory && t.nonceUsed && !t.posted && t.signer != nil && r.Header.Get("Content-Type") == "application/jose+json":
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || !t.validJWS(body) {
			clear(body)
			return nil, errRefused
		}
		r.Body = &ownedBody{Reader: bytes.NewReader(body), data: body}
		t.posted = true
		kind = "account"
	default:
		return nil, errRefused
	}
	if !t.allowed() {
		return nil, errRefused
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, errRefused
	}
	defer response.Body.Close()
	if response.ContentLength > maxBody || (response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") {
		return nil, errRefused
	}
	if kind == "nonce" {
		nonce := response.Header.Get("Replay-Nonce")
		decoded, err := base64.RawURLEncoding.DecodeString(nonce)
		if err != nil || len(response.Header.Values("Replay-Nonce")) != 1 || len(decoded) < 16 || len(decoded) > 256 || base64.RawURLEncoding.EncodeToString(decoded) != nonce || (response.StatusCode != 200 && response.StatusCode != 204) || !t.allowed() {
			return nil, errRefused
		}
		t.nonce = nonce
		response.Header = http.Header{"Replay-Nonce": {nonce}}
		response.Body = http.NoBody
		return response, nil
	}
	media, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (media != "application/json" && !(kind == "account" && media == "application/problem+json")) || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		return nil, errRefused
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || !strictObject(body) || !t.allowed() {
		clear(body)
		return nil, errRefused
	}
	defer clear(body)
	response.Header = response.Header.Clone()
	location := response.Header.Get("Location")
	locationCount := len(response.Header.Values("Location"))
	response.Header = make(http.Header)
	sanitized := body
	if kind == "directory" {
		if response.StatusCode != http.StatusOK || !validDirectory(body) || !validRegistrationMeta(body) {
			return nil, errRefused
		}
	} else {
		if t.lookup && response.StatusCode == http.StatusBadRequest && validAbsentAccount(body) {
			t.absent = true
			sanitized = []byte(`{"type":"urn:ietf:params:acme:error:accountDoesNotExist","status":400}`)
		} else {
			if media != "application/json" || locationCount != 1 || (response.StatusCode != http.StatusOK && !(!t.lookup && response.StatusCode == http.StatusCreated)) || !validAccountResponse(body, location) {
				return nil, errRefused
			}
			response.Header.Set("Location", location)
			// Strip extension/contact/Link/error metadata before the library parser.
			sanitized = []byte(`{"status":"valid"}`)
		}
	}
	copyBody := bytes.Clone(sanitized)
	response.Body = &ownedBody{Reader: bytes.NewReader(copyBody), data: copyBody}
	response.ContentLength = int64(len(copyBody))
	return response, nil
}

func strictObject(body []byte) bool {
	if len(body) == 0 || len(body) > maxBody || !utf8.Valid(body) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	budget := 2048
	if !uniqueValue(d, 0, &budget) {
		return false
	}
	if _, err := d.Token(); err != io.EOF {
		return false
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(body, &object) == nil && object != nil
}

func validRegistrationMeta(body []byte) bool {
	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil {
		return false
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(root["meta"], &meta) != nil || meta == nil {
		return false
	}
	var terms string
	if json.Unmarshal(meta["termsOfService"], &terms) != nil || !inventorystore.ValidStagingTermsURL(terms) {
		return false
	}
	for name, raw := range meta {
		if name != "termsOfService" && strings.EqualFold(name, "termsOfService") || name != "externalAccountRequired" && strings.EqualFold(name, "externalAccountRequired") {
			return false
		}
		if name == "externalAccountRequired" {
			var value bool
			if string(raw) == "null" || json.Unmarshal(raw, &value) != nil || value {
				return false
			}
		}
	}
	return true
}

func validAccountResponse(body []byte, location string) bool {
	if !validRegistrationAccountURL(location) {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return false
	}
	var status string
	if json.Unmarshal(fields["status"], &status) != nil || status != "valid" {
		return false
	}
	for name, raw := range fields {
		for _, canonical := range []string{"status", "orders", "contact", "termsOfServiceAgreed"} {
			if name != canonical && strings.EqualFold(name, canonical) {
				return false
			}
		}
		switch name {
		case "orders":
			var value string
			if json.Unmarshal(raw, &value) != nil || value != strings.Replace(location, "/acme/acct/", "/acme/orders/", 1) {
				return false
			}
		case "contact":
			var contacts []string
			if string(raw) == "null" || json.Unmarshal(raw, &contacts) != nil || len(contacts) != 0 {
				return false
			}
		case "termsOfServiceAgreed":
			if string(raw) != "true" {
				return false
			}
		}
	}
	return true
}

func validAbsentAccount(body []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return false
	}
	var problem string
	if json.Unmarshal(fields["type"], &problem) != nil || problem != "urn:ietf:params:acme:error:accountDoesNotExist" {
		return false
	}
	for name, raw := range fields {
		if name != "type" && strings.EqualFold(name, "type") || name != "status" && strings.EqualFold(name, "status") {
			return false
		}
		if name == "status" && string(raw) != "400" {
			return false
		}
	}
	return true
}

func (t *registrationTransport) validJWS(body []byte) bool {
	if len(body) > 4096 || !strictObject(body) {
		return false
	}
	var envelope map[string]string
	if json.Unmarshal(body, &envelope) != nil || len(envelope) != 3 {
		return false
	}
	decode := func(value string) ([]byte, bool) {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		return decoded, err == nil && base64.RawURLEncoding.EncodeToString(decoded) == value
	}
	protected, ok := decode(envelope["protected"])
	if !ok || !strictObject(protected) {
		return false
	}
	var header map[string]json.RawMessage
	if json.Unmarshal(protected, &header) != nil || len(header) != 4 {
		return false
	}
	var alg, nonce, destination string
	if json.Unmarshal(header["alg"], &alg) != nil || alg != "ES256" || json.Unmarshal(header["nonce"], &nonce) != nil || nonce != t.nonce || nonce == "" || json.Unmarshal(header["url"], &destination) != nil || destination != registerURL {
		return false
	}
	var jwk map[string]string
	if json.Unmarshal(header["jwk"], &jwk) != nil || len(jwk) != 4 || jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
		return false
	}
	public, err := t.signer.Public().(*ecdsa.PublicKey).Bytes()
	if err != nil || len(public) != 65 || public[0] != 4 || jwk["x"] != base64.RawURLEncoding.EncodeToString(public[1:33]) || jwk["y"] != base64.RawURLEncoding.EncodeToString(public[33:65]) {
		return false
	}
	payload, ok := decode(envelope["payload"])
	if !ok || !strictObject(payload) {
		return false
	}
	var fields map[string]bool
	if json.Unmarshal(payload, &fields) != nil || len(fields) != 1 || (!t.lookup && !fields["termsOfServiceAgreed"]) || (t.lookup && !fields["onlyReturnExisting"]) {
		return false
	}
	signature, ok := decode(envelope["signature"])
	return ok && len(signature) == 64
}
