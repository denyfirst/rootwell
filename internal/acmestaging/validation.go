package acmestaging

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/acmeplan"
	"golang.org/x/crypto/acme"
)

// DNSValidation accepts only acknowledged challenges on a saved order. Refresh
// never accepts a challenge, even when a prior request's outcome was uncertain.
func DNSValidation(ctx context.Context, permit func() bool, signer crypto.Signer, account string, saved acmeorder.Instructions, names []string, refresh bool) (acmeorder.Validation, error) {
	if !Available() {
		return acmeorder.Validation{}, errRefused
	}
	return dnsValidation(ctx, permit, liveDependencies(), signer, account, saved, names, refresh)
}

func dnsValidation(parent context.Context, permit func() bool, deps dependencies, signer crypto.Signer, account string, saved acmeorder.Instructions, names []string, refresh bool) (observation acmeorder.Validation, operationErr error) {
	var guard *orderTransport
	defer func() {
		if guard != nil {
			if operationErr != nil {
				observation = acmeorder.Validation{}
				operationErr = operationWaitFailure(guard.wait)
			} else {
				observation.Wait = guard.wait
			}
		}
	}()
	bad := func() (acmeorder.Validation, error) { return acmeorder.Validation{}, errRefused }
	if !validAccountSigner(signer) || !acmeorder.ValidInstructions(saved, account, names) || saved.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") {
		return bad()
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	allowed := func() bool { return ctx.Err() == nil && permit != nil && permit() }
	transport := pinnedTransport(ctx, allowed, deps)
	defer transport.CloseIdleConnections()
	guard = &orderTransport{base: transport, allowed: allowed, account: account, order: saved.URL, names: slices.Clone(names), used: map[string]bool{}, validation: true}
	client := &acme.Client{Key: signer, KID: acme.KeyID(account), DirectoryURL: acmeplan.Directory, UserAgent: "Rootwell-staging-dns-validation",
		HTTPClient: &http.Client{Transport: guard, CheckRedirect: func(*http.Request, []*http.Request) error { return errRefused }}, RetryBackoff: func(int, *http.Request, *http.Response) time.Duration { return 0 }}
	directory, err := client.Discover(ctx)
	if err != nil || !allowed() || !validRegistrationDirectory(directory) || directory.OrderURL != newOrderURL {
		return bad()
	}
	order, err := client.GetOrder(ctx, saved.URL)
	if err != nil || order == nil || !allowed() || order.URI != saved.URL || len(guard.authz) != len(names) {
		return bad()
	}
	result := acmeorder.Validation{URL: saved.URL, Expires: min(saved.Expires, guard.expires), OrderStatus: order.Status, Statuses: make([]string, len(names))}
	seen, destinations := map[string]bool{}, map[string]string{}
	accept := []*acme.Challenge{}
	for _, url := range guard.authz {
		a, err := client.GetAuthorization(ctx, url)
		if err != nil || a == nil || !allowed() {
			return bad()
		}
		name := a.Identifier.Value
		if a.Wildcard {
			name = "*." + name
		}
		i := slices.Index(names, name)
		if i < 0 || seen[name] || a.Identifier.Type != "dns" {
			return bad()
		}
		seen[name] = true
		result.Statuses[i] = a.Status
		result.Expires = min(result.Expires, a.Expires.UTC().Format("2006-01-02T15:04:05Z"))
		if a.Status != "pending" {
			continue
		}
		if len(a.Challenges) != 1 {
			return bad()
		}
		c := a.Challenges[0]
		digest, err := client.DNS01ChallengeRecord(c.Token)
		if err != nil || !saved.Records[i].Required || digest != saved.Records[i].Value || destinations[c.URI] != "" {
			return bad()
		}
		destinations[c.URI] = c.Token
		if c.Status == "pending" {
			accept = append(accept, &acme.Challenge{Type: "dns-01", URI: c.URI, Token: c.Token})
		}
	}
	state := acmeorder.ValidationState(result, names)
	if !allowed() || state == "" || result.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") {
		return bad()
	}
	// No challenge authority until the COMPLETE set, digests and verdict agree.
	if !refresh && state == "validation-waiting" {
		guard.challenges = destinations
		for _, c := range accept {
			if !allowed() {
				return bad()
			}
			if _, err := client.Accept(ctx, c); err != nil || !allowed() {
				return bad()
			}
		}
	}
	// Accept responses are not used as authorization verdicts. A later explicit
	// refresh must observe all valid authorizations AND a ready order.
	return result, nil
}

func readValidationChallenge(body []byte, expectedURL, expectedToken string) ([]byte, error) {
	clean, ok := orderFields(body, "type", "url", "status", "token", "error", "validated")
	var c struct {
		Type   string          `json:"type"`
		URL    string          `json:"url"`
		Status string          `json:"status"`
		Token  string          `json:"token"`
		Error  json.RawMessage `json:"error"`
	}
	if !ok || json.Unmarshal(clean, &c) != nil || c.Type != "dns-01" || c.URL != expectedURL || !acmeorder.ResourceURL(c.URL, "challenge") || !validOrderToken(c.Token) || c.Token != expectedToken || !slices.Contains([]string{"pending", "processing", "valid", "invalid"}, c.Status) || (len(c.Error) > 0 && (c.Status != "invalid" || !strictObject(c.Error))) {
		return nil, errRefused
	}
	return json.Marshal(struct {
		Type   string `json:"type"`
		URL    string `json:"url"`
		Status string `json:"status"`
		Token  string `json:"token"`
	}{c.Type, c.URL, c.Status, c.Token})
}

func readValidationAuthorization(body []byte, names []string) ([]byte, error) {
	clean, ok := orderFields(body, "identifier", "status", "expires", "wildcard", "challenges")
	var a struct {
		Identifier json.RawMessage   `json:"identifier"`
		Status     string            `json:"status"`
		Expires    string            `json:"expires"`
		Wildcard   bool              `json:"wildcard"`
		Challenges []json.RawMessage `json:"challenges"`
	}
	if !ok || json.Unmarshal(clean, &a) != nil || !slices.Contains([]string{"pending", "valid", "invalid", "expired", "revoked", "deactivated"}, a.Status) || !acmeorder.Time(a.Expires) || a.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") || len(a.Challenges) > 8 {
		return nil, errRefused
	}
	id, ok := identifier(a.Identifier)
	name := id.Value
	if a.Wildcard {
		name = "*." + name
	}
	if !ok || strings.HasPrefix(id.Value, "*.") || !slices.Contains(names, name) {
		return nil, errRefused
	}
	challenges := []json.RawMessage{}
	for _, raw := range a.Challenges {
		clean, ok := orderFields(raw, "type", "url", "status", "token", "error", "validated")
		var c struct{ Type, URL, Status, Token string }
		if !ok || json.Unmarshal(clean, &c) != nil || !acmeorder.ResourceURL(c.URL, "challenge") {
			return nil, errRefused
		}
		if c.Type != "dns-01" {
			continue
		}
		cJSON, err := readValidationChallenge(raw, c.URL, c.Token)
		if err != nil || len(challenges) != 0 || (a.Status == "pending" && c.Status != "pending" && c.Status != "processing") {
			return nil, errRefused
		}
		challenges = append(challenges, cJSON)
	}
	if a.Status == "pending" && len(challenges) != 1 {
		return nil, errRefused
	}
	return json.Marshal(struct {
		Identifier orderIdentifier   `json:"identifier"`
		Status     string            `json:"status"`
		Expires    string            `json:"expires"`
		Wildcard   bool              `json:"wildcard"`
		Challenges []json.RawMessage `json:"challenges"`
	}{id, a.Status, a.Expires, a.Wildcard, challenges})
}
