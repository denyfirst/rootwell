package acmestaging

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/providerretry"
	"github.com/denyfirst/rootwell/internal/renewalpolicy"
)

const renewalInfoURL = "https://" + host + "/acme/renewal-info"

// Internal protocol component only; no live export or runtime consumer before
// exact certificate-source custody, durable read intent/waits and opt-in UI.
type ariObservation struct {
	Available   bool
	Information renewalpolicy.Information
}

type ariFailure struct {
	Temporary bool
	Hint      providerretry.Hint
}

func (*ariFailure) Error() string { return "renewal information unavailable" }

func renewalInformation(parent context.Context, permit func() bool, deps dependencies, der []byte, replaced bool) (ariObservation, error) {
	bad := func() (ariObservation, error) { return ariObservation{}, &ariFailure{} }
	// Public ID computation performs no trust verification or OS certificate I/O.
	id, err := renewalpolicy.CertificateID(der)
	cert, parseErr := x509.ParseCertificate(der)
	started := time.Now().UTC()
	if err != nil || parseErr != nil || replaced || started.Before(cert.NotBefore) || !started.Before(cert.NotAfter) {
		return bad()
	}
	if _, err := renewalpolicy.FallbackWindow(renewalpolicy.Window{Start: cert.NotBefore, End: cert.NotAfter}); err != nil {
		return bad()
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	allowed := func() bool {
		now := time.Now().UTC()
		return ctx.Err() == nil && permit != nil && permit() && !now.Before(started) && now.Before(cert.NotAfter)
	}
	if !allowed() || deps.lookup == nil || deps.dial == nil || deps.tls == nil {
		return bad()
	}
	transport := pinnedTransport(ctx, allowed, deps)
	defer transport.CloseIdleConnections()
	s := ariSession{base: transport, allowed: allowed, used: map[string]bool{}}
	body, _, err := s.get(ctx, acmeplan.Directory, maxBody)
	if err != nil {
		return ariObservation{}, err
	}
	defer clear(body)
	if !validDirectory(body) || !allowed() {
		return bad()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return bad()
	}
	raw, supported := fields["renewalInfo"]
	if !supported {
		if !allowed() {
			return bad()
		}
		return ariObservation{}, nil
	}
	var endpoint string
	if json.Unmarshal(raw, &endpoint) != nil || endpoint != renewalInfoURL {
		return bad()
	}
	s.endpoint = endpoint + "/" + id
	body, wait, err := s.get(ctx, s.endpoint, renewalpolicy.MaxInformationBytes)
	if err != nil {
		return ariObservation{}, err
	}
	defer clear(body)
	info, err := renewalpolicy.ParseInformation(body, wait, time.Now().UTC())
	if err != nil || !allowed() || info.Window.End.After(cert.NotAfter) {
		return bad()
	}
	return ariObservation{Available: true, Information: info}, nil
}

type ariSession struct {
	base     http.RoundTripper
	allowed  func() bool
	endpoint string
	used     map[string]bool
}

func validARIURL(uri string) bool {
	if !strings.HasPrefix(uri, renewalInfoURL+"/") {
		return false
	}
	id := strings.TrimPrefix(uri, renewalInfoURL+"/")
	if len(id) > 128 {
		return false
	}
	left, right, ok := strings.Cut(id, ".")
	if !ok || left == "" || right == "" {
		return false
	}
	for _, part := range []string{left, right} {
		for _, c := range part {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	aki, err := base64.RawURLEncoding.Strict().DecodeString(left)
	serial, serialErr := base64.RawURLEncoding.Strict().DecodeString(right)
	if err != nil || serialErr != nil || len(aki) == 0 || len(aki) > 64 || len(serial) == 0 || len(serial) > 20 {
		return false
	}
	if serial[0]&0x80 != 0 || serial[0] == 0 && (len(serial) == 1 || serial[1]&0x80 == 0) {
		return false
	}
	return true
}

func (s *ariSession) get(ctx context.Context, uri string, limit int) ([]byte, []string, error) {
	bad := func() ([]byte, []string, error) { return nil, nil, &ariFailure{} }
	if s.allowed == nil || !s.allowed() || s.base == nil || s.used == nil || len(s.used) >= 2 || s.used[uri] || limit < 1 || limit > maxBody {
		return bad()
	}
	if uri != acmeplan.Directory && (s.endpoint == "" || uri != s.endpoint || !validARIURL(uri)) {
		return bad()
	}
	s.used[uri] = true
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return bad()
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("User-Agent", "Rootwell-staging-renewal-information")
	response, err := s.base.RoundTrip(r)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, nil, &ariFailure{Temporary: ctx.Err() == context.DeadlineExceeded}
	}
	if response == nil || response.Body == nil {
		return bad()
	}
	defer response.Body.Close()
	if !s.allowed() {
		return bad()
	}
	if response.StatusCode != http.StatusOK {
		return nil, nil, &ariFailure{Temporary: response.StatusCode >= 500 && response.StatusCode <= 599, Hint: providerretry.RetryAfter(response.Header.Values("Retry-After"), time.Now().UTC())}
	}
	media, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	encoding := response.Header.Get("Content-Encoding")
	if len(response.Header.Values("Content-Type")) != 1 || len(response.Header.Values("Content-Encoding")) > 1 {
		return bad()
	}
	if err != nil || media != "application/json" || params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8") || encoding != "" && encoding != "identity" || response.ContentLength > int64(limit) {
		return bad()
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		clear(body)
		return nil, nil, &ariFailure{Temporary: ctx.Err() == context.DeadlineExceeded}
	}
	if len(body) > limit || !s.allowed() {
		clear(body)
		return bad()
	}
	return body, response.Header.Values("Retry-After"), nil
}
