// Package acmestaging is an opt-in, directory-only outbound connector.
// It cannot create accounts, sign requests, or issue certificates.
package acmestaging

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/acmeplan"
	"golang.org/x/crypto/acme"
)

const host = "acme-staging-v02.api.letsencrypt.org"
const maxBody = 32 << 10

var errRefused = errors.New("staging connection could not be safely checked")

// Summary describes reachability only, never account or issuance readiness.
type Summary struct {
	Schema         string `json:"schema_version"`
	Provider       string `json:"provider"`
	Directory      string `json:"directory"`
	State          string `json:"state"`
	NetworkUsed    bool   `json:"network_used"`
	DomainsSent    bool   `json:"domains_sent"`
	Saved          bool   `json:"saved"`
	AccountCreated bool   `json:"account_created"`
	CanIssue       bool   `json:"can_issue"`
}

type dependencies struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	tls    *tls.Config
}

// Discover permits one staging directory GET after the caller authorizes it.
// permit must remain valid across DNS, dialing, sending and result publication.
// Already-sent bytes cannot be recalled if authorization is later revoked.
func Discover(ctx context.Context, permit func() bool) (Summary, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
	return discover(ctx, permit, dependencies{
		lookup: net.DefaultResolver.LookupNetIP,
		dial:   dialer.DialContext,
		tls:    &tls.Config{MinVersion: tls.VersionTLS12},
	})
}

func discover(ctx context.Context, permit func() bool, deps dependencies) (Summary, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	allowed := func() bool { return ctx.Err() == nil && permit != nil && permit() }
	if !allowed() {
		return Summary{}, errRefused
	}
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: deps.tls,
		TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 4 * time.Second,
		MaxResponseHeaderBytes: 8192, DisableCompression: true, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != host+":443" || !allowed() {
				return nil, errRefused
			}
			addresses, err := deps.lookup(ctx, "ip", host)
			if err != nil || len(addresses) == 0 || len(addresses) > 16 {
				return nil, errRefused
			}
			for _, ip := range addresses {
				if !publicAddress(ip) {
					return nil, errRefused
				}
			}
			if !allowed() {
				return nil, errRefused
			}
			// Numeric dialing pins this connection to the validated DNS answer.
			// TLS still verifies the original hostname using the system trust store.
			return deps.dial(ctx, "tcp", net.JoinHostPort(addresses[0].Unmap().String(), "443"))
		},
	}
	// Check authorization again after TLS, before handing the connection to HTTP.
	// No application request should start when cancellation/revocation happened
	// during DNS, dialing or the handshake.
	transport.DialTLSContext = func(_ context.Context, network, address string) (net.Conn, error) {
		// Transport may detach its dial context from request deadlines to reuse
		// connections. This one-use transport must retain the original deadline.
		conn, err := transport.DialContext(ctx, network, address)
		if err != nil {
			return nil, errRefused
		}
		config := deps.tls.Clone()
		config.ServerName = host
		secure := tls.Client(conn, config)
		handshakeCtx, stop := context.WithTimeout(ctx, 4*time.Second)
		defer stop()
		if secure.HandshakeContext(handshakeCtx) != nil || !allowed() {
			_ = conn.Close()
			return nil, errRefused
		}
		return secure, nil
	}
	defer transport.CloseIdleConnections()
	guard := &directoryTransport{base: transport, allowed: allowed}
	client := &acme.Client{
		DirectoryURL: acmeplan.Directory, UserAgent: "Rootwell-directory-check",
		HTTPClient:   &http.Client{Transport: guard, CheckRedirect: func(*http.Request, []*http.Request) error { return errRefused }},
		RetryBackoff: func(int, *http.Request, *http.Response) time.Duration { return 0 },
	}
	if _, err := client.Discover(ctx); err != nil || !allowed() {
		return Summary{}, errRefused
	}
	return Summary{Schema: "rootwell.acme.directory.v1", Provider: acmeplan.Provider,
		Directory: acmeplan.Directory, State: "directory-checked", NetworkUsed: true}, nil
}

type directoryTransport struct {
	base    http.RoundTripper
	allowed func() bool
	used    atomic.Bool
}

func (t *directoryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet || r.URL.String() != acmeplan.Directory ||
		r.Host != host || r.Body != nil || r.Header.Get("Authorization") != "" ||
		r.Header.Get("Cookie") != "" || !t.allowed() || t.used.Swap(true) {
		return nil, errRefused
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, errRefused
	}
	defer response.Body.Close()
	media, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	encoding := response.Header.Get("Content-Encoding")
	if err != nil || media != "application/json" ||
		(params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) ||
		response.StatusCode != http.StatusOK || (encoding != "" && encoding != "identity") ||
		response.ContentLength > maxBody {
		return nil, errRefused
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || !validDirectory(body) || !t.allowed() {
		clear(body)
		return nil, errRefused
	}
	// Nothing from the CA is reflected in local output. Feed only a bounded,
	// preflighted document to the maintained ACME parser; never follow its URLs.
	response.Body = &ownedBody{Reader: bytes.NewReader(body), data: body}
	response.Header = make(http.Header)
	return response, nil
}

type ownedBody struct {
	*bytes.Reader
	data []byte
}

func (b *ownedBody) Close() error { clear(b.data); return nil }

func publicAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range deniedPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return ip.Is4() || netip.MustParsePrefix("2000::/3").Contains(ip)
}

// Conservative policy: availability may be reduced for special-use addresses.
var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

func validDirectory(body []byte) bool {
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
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return false
	}
	known := map[string]bool{"newNonce": true, "newAccount": true, "newOrder": true, "revokeCert": true, "keyChange": true, "newAuthz": true, "renewalInfo": true, "meta": true}
	for name, raw := range fields {
		if !known[name] {
			for canonical := range known {
				if strings.EqualFold(name, canonical) {
					return false
				}
			}
			continue // Bounded extension fields are ignored, never followed.
		}
		if name == "meta" {
			var meta map[string]json.RawMessage
			if json.Unmarshal(raw, &meta) != nil || meta == nil {
				return false
			}
			continue // ToS/website may be another host; neither is fetched or accepted.
		}
		var endpoint string
		if json.Unmarshal(raw, &endpoint) != nil || !safeEndpoint(endpoint) {
			return false
		}
	}
	for _, name := range []string{"newNonce", "newAccount", "newOrder", "revokeCert", "keyChange"} {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}

func safeEndpoint(value string) bool {
	if len(value) > 1024 {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host != host || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || !strings.HasPrefix(u.Path, "/acme/") {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(u.Path, "/acme/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, c := range segment {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return u.String() == value
}

func uniqueValue(d *json.Decoder, depth int, budget *int) bool {
	*budget -= 1
	if depth > 8 || *budget < 0 {
		return false
	}
	token, err := d.Token()
	if err != nil {
		return false
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return true
	}
	if delim != '{' && delim != '[' {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return false
			}
			seen[name] = true
			*budget -= 1
		}
		if !uniqueValue(d, depth+1, budget) {
			return false
		}
	}
	end, err := d.Token()
	return err == nil && (delim == '{' && end == json.Delim('}') || delim == '[' && end == json.Delim(']'))
}
