package acmestaging

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/acmecertrequest"
	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/certinspect"
	"golang.org/x/crypto/acme"
)

const maxCertificatePEM = 352 << 10

// This connector is intentionally not exported or routed yet. Durable intent,
// a locked stored-CSR lease, receipt acceptance and atomic pair/provenance
// storage must precede its live integration. No runtime dependency override.
// A response is UNTRUSTED certificate input, never a storage/trust verdict.
type certificateObservation struct {
	State string
	DER   [][]byte
}

func certificateOrder(parent context.Context, permit func() bool, deps dependencies, signer crypto.Signer, account, order, expires string, names []string, private, csr []byte, refresh bool) (certificateObservation, error) {
	bad := func() (certificateObservation, error) { return certificateObservation{}, errRefused }
	if !validAccountSigner(signer) || !acmeorder.OrderURL(order, account) || !acmeorder.Time(expires) || expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") {
		return bad()
	}
	if _, err := acmecertrequest.Check(private, csr, names); err != nil {
		return bad()
	}
	accountPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	request, parseErr := x509.ParseCertificateRequest(csr)
	if err != nil || parseErr != nil || bytes.Equal(accountPublic, request.RawSubjectPublicKeyInfo) {
		return bad()
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	allowed := func() bool { return ctx.Err() == nil && permit != nil && permit() }
	if !allowed() {
		return bad()
	}
	transport := pinnedTransport(ctx, allowed, deps)
	defer transport.CloseIdleConnections()
	guard := &certificateTransport{base: transport, allowed: allowed, account: account, order: order, expires: expires, names: slices.Clone(names), csr: bytes.Clone(csr), refresh: refresh, used: map[string]bool{}}
	defer clear(guard.csr)
	client := &acme.Client{Key: signer, KID: acme.KeyID(account), DirectoryURL: acmeplan.Directory, UserAgent: "Rootwell-staging-certificate",
		HTTPClient: &http.Client{Transport: guard, CheckRedirect: func(*http.Request, []*http.Request) error { return errRefused }}, RetryBackoff: func(int, *http.Request, *http.Response) time.Duration { return 0 }}
	directory, err := client.Discover(ctx)
	if err != nil || !allowed() || !validRegistrationDirectory(directory) || directory.OrderURL != newOrderURL {
		return bad()
	}
	o, err := client.GetOrder(ctx, order)
	if err != nil || o == nil || !allowed() || o.URI != order || guard.expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") {
		return bad()
	}
	if refresh && o.Status != acme.StatusValid {
		return certificateObservation{State: o.Status}, nil
	}
	if (!refresh && o.Status != acme.StatusReady) || (refresh && o.Status != acme.StatusValid) {
		return bad()
	}
	// Re-observe the COMPLETE authorization set before any finalize/fetch.
	seen := map[string]bool{}
	for _, url := range guard.authz {
		a, err := client.GetAuthorization(ctx, url)
		if err != nil || a == nil || !allowed() || a.Status != acme.StatusValid || a.Identifier.Type != "dns" {
			return bad()
		}
		name := a.Identifier.Value
		if a.Wildcard {
			name = "*." + name
		}
		if !slices.Contains(names, name) || seen[name] {
			return bad()
		}
		seen[name] = true
		guard.expires = min(guard.expires, a.Expires.UTC().Format("2006-01-02T15:04:05Z"))
	}
	if len(seen) != len(names) || !allowed() || guard.expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") {
		return bad()
	}
	guard.authorized = true
	var der [][]byte
	if refresh {
		der, err = client.FetchCert(ctx, guard.certificate, true)
	} else {
		var certURL string
		der, certURL, err = client.CreateOrderCert(ctx, guard.finalize(), csr, true)
		if guard.processing && err != nil && allowed() && guard.expires > time.Now().UTC().Format("2006-01-02T15:04:05Z") {
			// The library's automatic WaitOrder is stopped BEFORE even its nonce
			// request. A checked processing observation is not issuance success.
			return certificateObservation{State: acme.StatusProcessing}, nil
		}
		if err == nil && certURL != guard.certificate {
			return bad()
		}
	}
	if err != nil || !allowed() || len(der) == 0 || !guard.fetched || guard.expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") {
		return bad()
	}
	return certificateObservation{State: "certificate-received", DER: der}, nil
}

type certificateTransport struct {
	base                                        http.RoundTripper
	allowed                                     func() bool
	account, order, expires, nonce, certificate string
	names, authz                                []string
	csr                                         []byte
	refresh, directory, read, authorized        bool
	finalized, processing, fetched, failed      bool
	used                                        map[string]bool
	requests                                    int
}

func (t *certificateTransport) finalize() string {
	return strings.Replace(t.order, "/acme/order/", "/acme/finalize/", 1)
}

func (t *certificateTransport) RoundTrip(r *http.Request) (res *http.Response, err error) {
	defer func() {
		if err != nil {
			t.failed = true
		}
	}()
	// Maximum: directory + nonce/read per order, 8 authz, finalize, cert = 23.
	// Once processing is observed NO request (including nonce/poll) is allowed.
	if t.failed || t.processing || !t.allowed() || t.expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") || t.requests >= 23 || r.Host != host || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		return nil, errRefused
	}
	kind, destination := "", r.URL.String()
	switch {
	case r.Method == http.MethodGet && destination == acmeplan.Directory && r.Body == nil && !t.directory:
		t.directory, kind = true, "directory"
	case r.Method == http.MethodHead && destination == nonceURL && r.Body == nil && t.directory && t.nonce == "":
		kind = "nonce"
	case r.Method == http.MethodPost && r.Header.Get("Content-Type") == "application/jose+json" && t.directory && t.nonce != "" && !t.used[destination]:
		switch {
		case destination == t.order && !t.read:
			kind = "order"
		case t.read && !t.authorized && slices.Contains(t.authz, destination):
			kind = "authorization"
		case !t.refresh && t.authorized && !t.finalized && destination == t.finalize():
			kind = "finalize"
		case t.authorized && t.certificate != "" && destination == t.certificate && (t.refresh || t.finalized):
			kind = "certificate"
		default:
			return nil, errRefused
		}
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 8193))
		if readErr != nil || !t.validJWS(body, destination, kind == "finalize") {
			clear(body)
			return nil, errRefused
		}
		r.Body = &ownedBody{Reader: bytes.NewReader(body), data: body}
		t.used[destination], t.nonce = true, ""
	default:
		return nil, errRefused
	}
	if !t.allowed() {
		return nil, errRefused
	}
	t.requests++
	res, err = t.base.RoundTrip(r)
	if err != nil {
		return nil, errRefused
	}
	defer res.Body.Close()
	if !t.allowed() || (res.Header.Get("Content-Encoding") != "" && res.Header.Get("Content-Encoding") != "identity") {
		return nil, errRefused
	}
	if kind == "nonce" {
		nonce := res.Header.Get("Replay-Nonce")
		if (res.StatusCode != 200 && res.StatusCode != 204) || len(res.Header.Values("Replay-Nonce")) != 1 || !validOrderToken(nonce) {
			return nil, errRefused
		}
		t.nonce = nonce
		res.Header, res.Body = http.Header{"Replay-Nonce": {nonce}}, http.NoBody
		return res, nil
	}
	if res.StatusCode != 200 || len(res.Header.Values("Location")) > 1 || (res.Header.Get("Location") != "" && ((kind != "order" && kind != "finalize") || res.Header.Get("Location") != t.order)) {
		return nil, errRefused
	}
	media, params, parseErr := mime.ParseMediaType(res.Header.Get("Content-Type"))
	limit, expectedMedia := maxBody, "application/json"
	if kind == "certificate" {
		limit, expectedMedia = maxCertificatePEM, "application/pem-certificate-chain"
	}
	if parseErr != nil || media != expectedMedia || len(params) > 1 || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) || (len(params) == 1 && params["charset"] == "") || res.ContentLength > int64(limit) {
		return nil, errRefused
	}
	body, readErr := io.ReadAll(io.LimitReader(res.Body, int64(limit)+1))
	defer clear(body)
	if readErr != nil || len(body) > limit || !t.allowed() {
		return nil, errRefused
	}
	var clean []byte
	switch kind {
	case "directory":
		if !validDirectory(body) || !validRegistrationMeta(body) {
			return nil, errRefused
		}
		clean = bytes.Clone(body)
	case "order", "finalize":
		clean, err = t.readOrder(body, kind == "finalize")
		if err != nil {
			return nil, errRefused
		}
		if kind == "order" {
			t.read = true
		} else {
			t.finalized = true
		}
	case "authorization":
		clean, err = readValidationAuthorization(body, t.names)
		if err != nil {
			return nil, errRefused
		}
	case "certificate":
		clean, err = strictCertificatePEM(body)
		if err != nil {
			return nil, errRefused
		}
		t.fetched = true
	default:
		return nil, errRefused
	}
	// Strip nonce/Link/Retry-After/provider metadata. No alternates or retries.
	res.Header = make(http.Header)
	if kind == "order" || kind == "finalize" {
		res.Header.Set("Location", t.order)
	}
	res.Body = &ownedBody{Reader: bytes.NewReader(clean), data: clean}
	res.ContentLength = int64(len(clean))
	return res, nil
}

func (t *certificateTransport) readOrder(body []byte, finalized bool) ([]byte, error) {
	clean, ok := orderFields(body, "status", "expires", "identifiers", "authorizations", "finalize", "certificate", "error", "notBefore", "notAfter")
	var w orderWire
	if !ok || json.Unmarshal(clean, &w) != nil || !acmeorder.Time(w.Expires) || w.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") || w.Finalize != t.finalize() || len(w.Identifiers) != len(t.names) || len(w.Authorizations) != len(t.names) {
		return nil, errRefused
	}
	if finalized {
		if w.Status != "processing" && w.Status != "valid" {
			return nil, errRefused
		}
	} else if !t.refresh {
		if w.Status != "ready" {
			return nil, errRefused
		}
	} else if !slices.Contains([]string{"pending", "ready", "processing", "valid", "invalid"}, w.Status) {
		return nil, errRefused
	}
	if len(w.Error) > 0 && (w.Status != "invalid" || !strictObject(w.Error)) {
		return nil, errRefused
	}
	certURL := ""
	if w.Status == "valid" {
		if json.Unmarshal(w.Certificate, &certURL) != nil || !certificateURL(certURL) {
			return nil, errRefused
		}
	} else if len(w.Certificate) != 0 {
		return nil, errRefused
	}
	names, ids := []string{}, []orderIdentifier{}
	for _, raw := range w.Identifiers {
		id, ok := identifier(raw)
		if !ok {
			return nil, errRefused
		}
		names, ids = append(names, id.Value), append(ids, id)
	}
	slices.Sort(names)
	if !slices.Equal(names, t.names) {
		return nil, errRefused
	}
	authz := slices.Clone(w.Authorizations)
	slices.Sort(authz)
	for i, url := range authz {
		if !acmeorder.ResourceURL(url, "authorization") || (i > 0 && url == authz[i-1]) {
			return nil, errRefused
		}
	}
	if finalized && !slices.Equal(authz, t.authz) {
		return nil, errRefused
	}
	t.authz, t.expires, t.certificate = authz, min(t.expires, w.Expires), certURL
	t.processing = finalized && w.Status == "processing"
	return json.Marshal(struct {
		Status         string            `json:"status"`
		Expires        string            `json:"expires"`
		Identifiers    []orderIdentifier `json:"identifiers"`
		Authorizations []string          `json:"authorizations"`
		Finalize       string            `json:"finalize"`
		Certificate    string            `json:"certificate,omitempty"`
	}{w.Status, w.Expires, ids, authz, w.Finalize, certURL})
}

func certificateURL(value string) bool {
	const prefix = acmeorder.Origin + "/acme/cert/"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	id := strings.TrimPrefix(value, prefix)
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (t *certificateTransport) validJWS(body []byte, destination string, finalize bool) bool {
	if len(body) > 8192 || !strictObject(body) {
		return false
	}
	var envelope map[string]string
	if json.Unmarshal(body, &envelope) != nil || len(envelope) != 3 {
		return false
	}
	decode := func(s string) ([]byte, bool) {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
		return raw, err == nil && base64.RawURLEncoding.EncodeToString(raw) == s
	}
	protected, ok := decode(envelope["protected"])
	if !ok || !strictObject(protected) {
		return false
	}
	var h map[string]string
	if json.Unmarshal(protected, &h) != nil || len(h) != 4 || h["alg"] != "ES256" || h["kid"] != t.account || h["nonce"] != t.nonce || h["url"] != destination {
		return false
	}
	payload, ok := decode(envelope["payload"])
	if !ok {
		return false
	}
	if finalize {
		var fields map[string]string
		if !strictObject(payload) || json.Unmarshal(payload, &fields) != nil || len(fields) != 1 || fields["csr"] != base64.RawURLEncoding.EncodeToString(t.csr) {
			return false
		}
	} else if len(payload) != 0 {
		return false
	}
	sig, ok := decode(envelope["signature"])
	return ok && len(sig) == 64
}

// Standard PEM decoding can skip leading garbage. Require exact public block
// boundaries and no headers/private/trailing data BEFORE the upstream decoder.
func strictCertificatePEM(input []byte) ([]byte, error) {
	if len(input) == 0 || len(input) > maxCertificatePEM {
		return nil, errRefused
	}
	rest, total, count := bytes.TrimSpace(input), 0, 0
	seen := map[string]bool{}
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errRefused
		}
		end := bytes.Index(rest, []byte("-----END CERTIFICATE-----"))
		if end < 0 {
			return nil, errRefused
		}
		end += len("-----END CERTIFICATE-----")
		if bytes.Count(rest[:end], []byte("-----BEGIN ")) != 1 {
			return nil, errRefused
		}
		// Decode only the first envelope, so pem.Decode cannot skip a broken
		// first block and silently select a later valid one.
		block, leftover := pem.Decode(rest[:end])
		tail := rest[end:]
		if block == nil || len(bytes.TrimSpace(leftover)) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) > 48<<10 || count >= 5 {
			return nil, errRefused
		}
		c, encoding, err := certinspect.Parse(block.Bytes)
		if err != nil || encoding != certinspect.EncodingDER || !bytes.Equal(c.Raw, block.Bytes) || seen[string(block.Bytes)] {
			return nil, errRefused
		}
		seen[string(block.Bytes)] = true
		total, count = total+len(block.Bytes), count+1
		if total > 256<<10 {
			return nil, errRefused
		}
		rest = bytes.TrimSpace(tail)
	}
	if count == 0 {
		return nil, errRefused
	}
	return bytes.Clone(input), nil
}
