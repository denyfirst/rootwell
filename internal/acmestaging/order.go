package acmestaging

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/acmeplan"
	"golang.org/x/crypto/acme"
)

const newOrderURL = acmeorder.Origin + "/acme/new-order"

// DNSOrder only prepares instructions. It cannot accept a challenge, finalize
// an order, fetch a certificate or provision DNS. Empty order means creation;
// otherwise only the exact already-checkpointed order can be read.
func DNSOrder(ctx context.Context, permit func() bool, signer crypto.Signer, account, order string, names []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
	if !Available() {
		return acmeorder.Instructions{}, errRefused
	}
	return dnsOrder(ctx, permit, liveDependencies(), signer, account, order, names, checkpoint)
}

func dnsOrder(parent context.Context, permit func() bool, deps dependencies, signer crypto.Signer, account, order string, names []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
	bad := func() (acmeorder.Instructions, error) { return acmeorder.Instructions{}, errRefused }
	if !validAccountSigner(signer) || !acmeorder.AccountURL(account) || !acmeorder.CanonicalNames(names) || (order == "" && checkpoint == nil) || (order != "" && !acmeorder.OrderURL(order, account)) {
		return bad()
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	allowed := func() bool { return ctx.Err() == nil && permit != nil && permit() }
	transport := pinnedTransport(ctx, allowed, deps)
	defer transport.CloseIdleConnections()
	guard := &orderTransport{base: transport, allowed: allowed, account: account, order: order, names: slices.Clone(names), checkpoint: checkpoint, used: map[string]bool{}}
	client := &acme.Client{Key: signer, KID: acme.KeyID(account), DirectoryURL: acmeplan.Directory, UserAgent: "Rootwell-staging-manual-dns",
		HTTPClient: &http.Client{Transport: guard, CheckRedirect: func(*http.Request, []*http.Request) error { return errRefused }}, RetryBackoff: func(int, *http.Request, *http.Response) time.Duration { return 0 }}
	directory, err := client.Discover(ctx)
	if err != nil || !allowed() || !validRegistrationDirectory(directory) || directory.OrderURL != newOrderURL {
		return bad()
	}
	var result *acme.Order
	if order == "" {
		result, err = client.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	} else {
		result, err = client.GetOrder(ctx, order)
	}
	if err != nil || result == nil || !allowed() || result.URI != guard.order || len(guard.authz) != len(names) {
		return bad()
	}
	info := acmeorder.Instructions{URL: guard.order, Expires: guard.expires, Records: make([]acmeorder.TXT, len(names))}
	seen := map[string]bool{}
	for _, url := range guard.authz {
		a, err := client.GetAuthorization(ctx, url)
		if err != nil || a == nil || !allowed() {
			return bad()
		}
		name := a.Identifier.Value
		if a.Wildcard {
			name = "*." + name
		}
		index := slices.Index(names, name)
		if index < 0 || seen[name] || a.Identifier.Type != "dns" || !a.Expires.After(time.Now()) {
			return bad()
		}
		seen[name] = true
		record := acmeorder.TXT{Domain: name, Name: "_acme-challenge." + strings.TrimPrefix(name, "*.")}
		if a.Status == acme.StatusPending {
			var challenge *acme.Challenge
			for _, c := range a.Challenges {
				if c.Type == "dns-01" {
					if challenge != nil {
						return bad()
					}
					challenge = c
				}
			}
			if challenge == nil || challenge.Status != acme.StatusPending || !validOrderToken(challenge.Token) || !acmeorder.ResourceURL(challenge.URI, "challenge") {
				return bad()
			}
			record.Required = true
			record.Value, err = client.DNS01ChallengeRecord(challenge.Token)
			if err != nil {
				return bad()
			}
		} else if a.Status != acme.StatusValid {
			return bad()
		}
		info.Records[index] = record
		// An authorization may expire before its order. Persist the earliest
		// deadline rather than presenting stale instructions as usable.
		if expires := a.Expires.UTC().Format("2006-01-02T15:04:05Z"); expires < info.Expires {
			info.Expires = expires
		}
	}
	if !allowed() || !acmeorder.ValidInstructions(info, account, names) {
		return bad()
	}
	return info, nil
}

type orderTransport struct {
	base                           http.RoundTripper
	allowed                        func() bool
	account, order, nonce, expires string
	names, authz                   []string
	checkpoint                     func(string) error
	directory, orderRead, failed   bool
	requests                       int
	used                           map[string]bool
}

func (t *orderTransport) RoundTrip(r *http.Request) (response *http.Response, err error) {
	// Any refusal closes this operation's authority; the maintained client's
	// internal retry paths cannot turn a failure into another request.
	defer func() {
		if err != nil {
			t.failed = true
		}
	}()
	if t.failed || !t.allowed() || t.requests >= 19 || r.Host != host || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		return nil, errRefused
	}
	kind := ""
	switch {
	case r.Method == http.MethodGet && r.URL.String() == acmeplan.Directory && r.Body == nil && !t.directory:
		t.directory = true
		kind = "directory"
	case r.Method == http.MethodHead && r.URL.String() == nonceURL && r.Body == nil && t.directory && t.nonce == "":
		kind = "nonce"
	case r.Method == http.MethodPost && r.Header.Get("Content-Type") == "application/jose+json" && t.directory && t.nonce != "" && !t.used[r.URL.String()]:
		destination := r.URL.String()
		if !t.orderRead && ((t.order == "" && destination == newOrderURL) || (t.order != "" && destination == t.order)) {
			kind = "order"
		} else if t.orderRead && slices.Contains(t.authz, destination) {
			kind = "authorization"
		} else {
			return nil, errRefused
		}
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 4097))
		if readErr != nil || !t.validJWS(body, destination, kind == "order" && t.order == "") {
			clear(body)
			return nil, errRefused
		}
		r.Body = &ownedBody{Reader: bytes.NewReader(body), data: body}
		t.used[destination] = true
		t.nonce = ""
	default:
		return nil, errRefused
	}
	if !t.allowed() {
		return nil, errRefused
	}
	t.requests++
	response, err = t.base.RoundTrip(r)
	if err != nil {
		return nil, errRefused
	}
	defer response.Body.Close()
	if !t.allowed() {
		return nil, errRefused
	}
	if kind == "order" {
		location := response.Header.Get("Location")
		if t.order == "" {
			if response.StatusCode != 201 || len(response.Header.Values("Location")) != 1 || !acmeorder.OrderURL(location, t.account) {
				return nil, errRefused
			}
			// Checkpoint before media/length/body validation, including a stalled
			// response. A failure after creation must retain the same order URI.
			if t.checkpoint == nil || t.checkpoint(location) != nil || !t.allowed() {
				return nil, errRefused
			}
			t.order = location
		} else if response.StatusCode != 200 || len(response.Header.Values("Location")) > 1 || (location != "" && location != t.order) {
			return nil, errRefused
		}
	}
	if response.ContentLength > maxBody || (response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") {
		return nil, errRefused
	}
	if kind == "nonce" {
		nonce := response.Header.Get("Replay-Nonce")
		if (response.StatusCode != 200 && response.StatusCode != 204) || len(response.Header.Values("Replay-Nonce")) != 1 || !validOrderToken(nonce) {
			return nil, errRefused
		}
		t.nonce = nonce
		response.Header = http.Header{"Replay-Nonce": {nonce}}
		response.Body = http.NoBody
		return response, nil
	}
	media, params, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if parseErr != nil || media != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) || (kind != "order" && response.StatusCode != 200) {
		return nil, errRefused
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	defer clear(body)
	if readErr != nil || !strictObject(body) || !t.allowed() {
		return nil, errRefused
	}
	var sanitized []byte
	switch kind {
	case "directory":
		if !validDirectory(body) || !validRegistrationMeta(body) {
			return nil, errRefused
		}
		sanitized = bytes.Clone(body)
	case "order":
		sanitized, err = t.readOrder(body)
		if err != nil {
			return nil, errRefused
		}
		t.orderRead = true
	case "authorization":
		sanitized, err = readOrderAuthorization(body, t.names)
		if err != nil {
			return nil, errRefused
		}
	default:
		return nil, errRefused
	}
	response.Header = make(http.Header)
	if kind == "order" {
		response.Header.Set("Location", t.order)
	}
	response.Body = &ownedBody{Reader: bytes.NewReader(sanitized), data: sanitized}
	response.ContentLength = int64(len(sanitized))
	return response, nil
}

func validOrderToken(value string) bool {
	if len(value) < 22 || len(value) > 342 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) >= 16 && len(raw) <= 256 && base64.RawURLEncoding.EncodeToString(raw) == value
}

// Strip bounded unknown extension data; reject aliases/null of known fields
// before encoding/json's case-insensitive matching can reinterpret them.
func orderFields(body []byte, names ...string) ([]byte, bool) {
	if !strictObject(body) {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return nil, false
	}
	clean := map[string]json.RawMessage{}
	for name, raw := range fields {
		for _, canonical := range names {
			if strings.EqualFold(name, canonical) {
				if name != canonical || string(raw) == "null" {
					return nil, false
				}
				clean[name] = raw
			}
		}
	}
	out, err := json.Marshal(clean)
	return out, err == nil
}

type orderIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
type orderWire struct {
	Status         string            `json:"status"`
	Expires        string            `json:"expires"`
	Identifiers    []json.RawMessage `json:"identifiers"`
	Authorizations []string          `json:"authorizations"`
	Finalize       string            `json:"finalize"`
	Certificate    json.RawMessage   `json:"certificate,omitempty"`
	Error          json.RawMessage   `json:"error,omitempty"`
}

func identifier(raw []byte) (orderIdentifier, bool) {
	clean, ok := orderFields(raw, "type", "value")
	var id orderIdentifier
	valid := ok && json.Unmarshal(clean, &id) == nil && id.Type == "dns" && id.Value != ""
	return id, valid
}

func (t *orderTransport) readOrder(body []byte) ([]byte, error) {
	clean, ok := orderFields(body, "status", "expires", "identifiers", "authorizations", "finalize", "certificate", "error", "notBefore", "notAfter")
	var w orderWire
	if !ok || json.Unmarshal(clean, &w) != nil || (w.Status != "pending" && w.Status != "ready") || !acmeorder.Time(w.Expires) || w.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") || len(w.Certificate) > 0 || len(w.Error) > 0 || len(w.Identifiers) != len(t.names) || len(w.Authorizations) != len(t.names) || w.Finalize != strings.Replace(t.order, "/acme/order/", "/acme/finalize/", 1) {
		return nil, errRefused
	}
	names := []string{}
	ids := []orderIdentifier{}
	for _, raw := range w.Identifiers {
		id, ok := identifier(raw)
		if !ok {
			return nil, errRefused
		}
		names = append(names, id.Value)
		ids = append(ids, id)
	}
	slices.Sort(names)
	if !slices.Equal(names, t.names) {
		return nil, errRefused
	}
	seen := map[string]bool{}
	for _, url := range w.Authorizations {
		if !acmeorder.ResourceURL(url, "authorization") || seen[url] {
			return nil, errRefused
		}
		seen[url] = true
	}
	t.authz = slices.Clone(w.Authorizations)
	t.expires = w.Expires
	return json.Marshal(struct {
		Status         string            `json:"status"`
		Expires        string            `json:"expires"`
		Identifiers    []orderIdentifier `json:"identifiers"`
		Authorizations []string          `json:"authorizations"`
	}{w.Status, w.Expires, ids, w.Authorizations})
}

func readOrderAuthorization(body []byte, names []string) ([]byte, error) {
	clean, ok := orderFields(body, "identifier", "status", "expires", "wildcard", "challenges")
	var w struct {
		Identifier json.RawMessage   `json:"identifier"`
		Status     string            `json:"status"`
		Expires    string            `json:"expires"`
		Wildcard   bool              `json:"wildcard"`
		Challenges []json.RawMessage `json:"challenges"`
	}
	if !ok || json.Unmarshal(clean, &w) != nil || (w.Status != "pending" && w.Status != "valid") || !acmeorder.Time(w.Expires) || w.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") || len(w.Challenges) > 8 {
		return nil, errRefused
	}
	id, ok := identifier(w.Identifier)
	name := id.Value
	if w.Wildcard {
		name = "*." + name
	}
	if !ok || strings.HasPrefix(id.Value, "*.") || !slices.Contains(names, name) {
		return nil, errRefused
	}
	challenges := []json.RawMessage{}
	dns := 0
	for _, raw := range w.Challenges {
		c, ok := orderFields(raw, "type", "url", "status", "token", "error", "validated")
		var challenge struct {
			Type, URL, Status, Token string
			Error                    json.RawMessage
		}
		if !ok || json.Unmarshal(c, &challenge) != nil || !acmeorder.ResourceURL(challenge.URL, "challenge") || len(challenge.Error) > 0 {
			return nil, errRefused
		}
		if challenge.Type == "dns-01" {
			dns++
			if dns > 1 || (w.Status == "pending" && (challenge.Status != "pending" || !validOrderToken(challenge.Token))) {
				return nil, errRefused
			}
			challenges = append(challenges, c)
		}
	}
	if w.Status == "pending" && dns != 1 {
		return nil, errRefused
	}
	return json.Marshal(struct {
		Identifier orderIdentifier   `json:"identifier"`
		Status     string            `json:"status"`
		Expires    string            `json:"expires"`
		Wildcard   bool              `json:"wildcard"`
		Challenges []json.RawMessage `json:"challenges"`
	}{id, w.Status, w.Expires, w.Wildcard, challenges})
}

func (t *orderTransport) validJWS(body []byte, destination string, create bool) bool {
	if len(body) > 4096 || !strictObject(body) {
		return false
	}
	var envelope map[string]string
	if json.Unmarshal(body, &envelope) != nil || len(envelope) != 3 {
		return false
	}
	decode := func(value string) ([]byte, bool) {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
		return raw, err == nil && base64.RawURLEncoding.EncodeToString(raw) == value
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
	if create {
		if !strictObject(payload) {
			return false
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(payload, &fields) != nil || len(fields) != 1 {
			return false
		}
		var ids []json.RawMessage
		if json.Unmarshal(fields["identifiers"], &ids) != nil || len(ids) != len(t.names) {
			return false
		}
		for i, raw := range ids {
			id, ok := identifier(raw)
			var exact map[string]json.RawMessage
			if !ok || json.Unmarshal(raw, &exact) != nil || len(exact) != 2 || id.Value != t.names[i] {
				return false
			}
		}
	} else if len(payload) != 0 {
		return false
	}
	signature, ok := decode(envelope["signature"])
	return ok && len(signature) == 64
}
