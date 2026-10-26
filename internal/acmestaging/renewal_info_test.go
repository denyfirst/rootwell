package acmestaging

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/renewalpolicy"
	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

func ariCertificate(t *testing.T, from, to time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic ARI parent"}, SubjectKeyId: []byte{1, 2, 3}}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(128), DNSNames: []string{"ari.rootwell.invalid"}, NotBefore: from, NotAfter: to}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parent, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
func ariDirectory(endpoint string) string {
	return strings.TrimSuffix(directoryJSON(), "}") + `,"renewalInfo":"` + endpoint + `"}`
}
func ariBody(at time.Time) string {
	return `{"suggestedWindow":{"start":"` + at.Add(24*time.Hour).Format(time.RFC3339) + `","end":"` + at.Add(48*time.Hour).Format(time.RFC3339) + `"},"explanationURL":"https://error-sentinel.invalid/never-follow"}`
}

func TestARIProtocolTwoPinnedPublicGETsNoCredentialsOrRedirects(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	now := time.Now().UTC().Truncate(time.Second)
	der := ariCertificate(t, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	id, err := renewalpolicy.CertificateID(der)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	deps, lookups := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
		step := calls.Add(1)
		if r.Method != "GET" || r.Host != host || r.TLS.ServerName != host || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Encoding") != "" || r.Header.Get("Accept") != "application/json" {
			t.Error("unexpected authority/metadata")
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Error("public read uploaded a body")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if step == 1 {
			if r.URL.RequestURI() != "/directory" {
				t.Error("wrong directory")
			}
			_, _ = io.WriteString(w, ariDirectory(renewalInfoURL))
			return
		}
		if step != 2 || r.URL.RequestURI() != "/acme/renewal-info/"+id {
			t.Error("wrong certificate/source/count")
		}
		w.Header().Set("Retry-After", "21600")
		_, _ = io.WriteString(w, ariBody(now))
	})
	result, err := renewalInformation(context.Background(), func() bool { return true }, deps, der, false)
	if err != nil || !result.Available || !result.Information.Window.Start.Equal(now.Add(24*time.Hour)) || result.Information.CheckAfter.Sub(result.Information.CheckedAt) != 6*time.Hour || calls.Load() != 2 || lookups.Load() != 2 {
		t.Fatal("valid scoped ARI read refused", err, result)
	}
}

func TestARIProtocolMissingAdvertisementDoesNotFetchCertificateID(t *testing.T) {
	now := time.Now().UTC()
	der := ariCertificate(t, now.Add(-time.Hour), now.Add(time.Hour))
	var calls atomic.Int32
	deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/directory" {
			t.Error("unadvertised ARI fetched")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, directoryJSON())
	})
	result, err := renewalInformation(context.Background(), func() bool { return true }, deps, der, false)
	if err != nil || !reflect.DeepEqual(result, ariObservation{}) || calls.Load() != 1 {
		t.Fatal("unsupported provider not distinguished", err)
	}
}

func TestARIScopedReceiptBindsUnsupportedAndFixedFailure(t *testing.T) {
	now := time.Now().UTC()
	der := ariCertificate(t, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	id, err := renewalpolicy.CertificateID(der)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"unsupported", "available", "wait"} {
		t.Run(mode, func(t *testing.T) {
			deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "3600")
				if mode == "wait" {
					w.Header().Set("Retry-After", "3600")
					w.WriteHeader(503)
					return
				}
				if r.URL.Path == "/directory" {
					if mode == "unsupported" {
						_, _ = io.WriteString(w, directoryJSON())
					} else {
						_, _ = io.WriteString(w, ariDirectory(renewalInfoURL))
					}
					return
				}
				_, _ = io.WriteString(w, ariBody(now))
			})
			result, err := renewalReceipt(context.Background(), func() bool { return true }, deps, der)
			if mode == "wait" {
				var failure *renewalrecord.Failure
				if !errors.As(err, &failure) || !failure.Temporary || failure.Hint.NotBefore.IsZero() || result != (renewalrecord.Observation{}) {
					t.Fatal("provider wait or zero result lost", err)
				}
				return
			}
			if err != nil || result.CertificateID != id || result.Available != (mode == "available") {
				t.Fatal("source-bound receipt missing", err)
			}
		})
	}
}

func TestARINativeExportRefusesBeforeDNS(t *testing.T) {
	if Available() {
		t.Skip("native refusal only")
	}
	result, err := RenewalInformation(context.Background(), func() bool { t.Fatal("native permit called"); return true }, nil)
	if err == nil || result != (renewalrecord.Observation{}) {
		t.Fatal("native acquired ARI network")
	}
}

func TestARIProtocolSourcePermissionAndExpiryRefuseBeforeDNS(t *testing.T) {
	now := time.Now().UTC()
	good := ariCertificate(t, now.Add(-time.Hour), now.Add(time.Hour))
	deps := dependencies{tls: &tls.Config{MinVersion: tls.VersionTLS12}, lookup: func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("unapproved ARI resolved DNS")
		return nil, errors.New("DNS-error-sentinel")
	}, dial: func(context.Context, string, string) (net.Conn, error) {
		t.Error("unapproved ARI dialed")
		return nil, nil
	}}
	for _, tc := range []struct {
		der      []byte
		replaced bool
		permit   func() bool
	}{
		{good, true, func() bool { return true }}, {good, false, nil}, {good, false, func() bool { return false }},
		{nil, false, func() bool { return true }}, {ariCertificate(t, now.Add(-2*time.Hour), now.Add(-time.Hour)), false, func() bool { return true }},
		{ariCertificate(t, now.Add(time.Hour), now.Add(2*time.Hour)), false, func() bool { return true }},
	} {
		result, err := renewalInformation(context.Background(), tc.permit, deps, tc.der, tc.replaced)
		if err == nil || !reflect.DeepEqual(result, ariObservation{}) || strings.Contains(err.Error(), "sentinel") {
			t.Fatal("invalid scope/permission released data")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := renewalInformation(ctx, func() bool { return true }, deps, good, false); err == nil || result.Available {
		t.Fatal("cancelled ARI started")
	}
	if result, err := renewalInformation(context.Background(), func() bool { return true }, dependencies{}, good, false); err == nil || !reflect.DeepEqual(result, ariObservation{}) {
		t.Fatal("incomplete transport accepted")
	}
}

func TestARIProtocolUntrustedResponsesCannotAddNetworkOrPartialInformation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	der := ariCertificate(t, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	for _, tc := range []struct {
		name      string
		directory string
		reply     func(http.ResponseWriter)
		temporary bool
		calls     int
	}{
		{"other-host", ariDirectory("https://error-sentinel.invalid/acme/renewal-info"), nil, false, 1},
		{"wrong-resource", ariDirectory("https://" + host + "/acme/new-acct"), nil, false, 1},
		{"trailing-slash", ariDirectory(renewalInfoURL + "/"), nil, false, 1},
		{"redirect", "", func(w http.ResponseWriter) {
			w.Header().Set("Location", "http://127.0.0.1/error-sentinel")
			w.WriteHeader(302)
		}, false, 2},
		{"error", "", func(w http.ResponseWriter) { w.WriteHeader(404); _, _ = io.WriteString(w, "error-sentinel") }, false, 2},
		{"temporary", "", func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(503)
			_, _ = io.WriteString(w, "error-sentinel")
		}, true, 2},
		{"bad-type", "", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, ariBody(now))
		}, false, 2},
		{"duplicate-type", "", func(w http.ResponseWriter) {
			w.Header().Add("Content-Type", "application/json")
			_, _ = io.WriteString(w, ariBody(now))
		}, false, 2},
		{"encoding", "", func(w http.ResponseWriter) {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = io.WriteString(w, ariBody(now))
		}, false, 2},
		{"oversize", "", func(w http.ResponseWriter) {
			_, _ = io.WriteString(w, strings.Repeat("x", renewalpolicy.MaxInformationBytes+1))
		}, false, 2},
		{"bad-json", "", func(w http.ResponseWriter) {
			_, _ = io.WriteString(w, `{"suggestedWindow":null,"error":"error-sentinel"}`)
		}, false, 2},
		{"past-expiry", "", func(w http.ResponseWriter) { _, _ = io.WriteString(w, ariBody(now.Add(100*24*time.Hour))) }, false, 2},
		{"duplicate-wait", "", func(w http.ResponseWriter) {
			w.Header().Add("Retry-After", "120")
			_, _ = io.WriteString(w, ariBody(now))
		}, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/directory" {
					d := tc.directory
					if d == "" {
						d = ariDirectory(renewalInfoURL)
					}
					_, _ = io.WriteString(w, d)
					return
				}
				w.Header().Set("Retry-After", "21600")
				tc.reply(w)
			})
			result, err := renewalInformation(context.Background(), func() bool { return true }, deps, der, false)
			var failure *ariFailure
			if err == nil || !errors.As(err, &failure) || failure.Temporary != tc.temporary || !reflect.DeepEqual(result, ariObservation{}) || strings.Contains(err.Error(), "sentinel") || calls.Load() != int32(tc.calls) {
				t.Fatal("unsafe response or partial data", err, result, calls.Load())
			}
			if tc.temporary && (failure.Hint.Blocked || failure.Hint.NotBefore.IsZero()) {
				t.Fatal("provider wait dropped")
			}
		})
	}
}

func TestARIProtocolRevocationAndDeadlineCannotPublishLateResult(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	der := ariCertificate(t, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	for _, atDirectory := range []bool{false, true} {
		var calls atomic.Int32
		var permitted atomic.Bool
		permitted.Store(true)
		deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/directory" {
				if atDirectory {
					permitted.Store(false)
				}
				_, _ = io.WriteString(w, ariDirectory(renewalInfoURL))
				return
			}
			permitted.Store(false)
			w.Header().Set("Retry-After", "21600")
			_, _ = io.WriteString(w, ariBody(now))
		})
		result, err := renewalInformation(context.Background(), permitted.Load, deps, der, false)
		want := int32(2)
		if atDirectory {
			want = 1
		}
		if err == nil || !reflect.DeepEqual(result, ariObservation{}) || calls.Load() != want {
			t.Fatal("revoked result published")
		}
	}
	deps, _ := fakeCA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/directory" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, ariDirectory(renewalInfoURL))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "21600")
		w.WriteHeader(200)
		if flush, ok := w.(http.Flusher); ok {
			flush.Flush()
		}
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := renewalInformation(ctx, func() bool { return true }, deps, der, false)
	if err == nil || !reflect.DeepEqual(result, ariObservation{}) {
		t.Fatal("slow body accepted")
	}
}

type ariRoundTrip func(*http.Request) (*http.Response, error)

func (f ariRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestARIProtocolOneUseURIAndRequestBudget(t *testing.T) {
	calls := 0
	base := ariRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.Body != nil || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("request gained authority")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})
	endpoint := renewalInfoURL + "/AQID.AIA"
	for _, uri := range []string{"http://" + host + "/acme/renewal-info/AQID.AIA", renewalInfoURL + "/../admin", endpoint + "?secret=sentinel", endpoint + "#fragment", endpoint + "/extra", renewalInfoURL + "/AQID.%2e", renewalInfoURL + "/AQID.AIA.other", renewalInfoURL + "/X.X", renewalInfoURL + "/AQID.AA", renewalInfoURL + "/AQID.gA", renewalInfoURL + "/AQID.AAE", "https://error-sentinel.invalid/acme/renewal-info/AQID.AIA"} {
		s := ariSession{base: base, allowed: func() bool { return true }, endpoint: uri, used: map[string]bool{}}
		if out, wait, err := s.get(context.Background(), uri, 8192); err == nil || out != nil || wait != nil {
			t.Fatal("unapproved URI used")
		}
	}
	if calls != 0 {
		t.Fatal("unsafe URL reached transport")
	}
	s := ariSession{base: base, allowed: func() bool { return true }, endpoint: endpoint, used: map[string]bool{}}
	for _, uri := range []string{acmeplan.Directory, endpoint} {
		if _, _, err := s.get(context.Background(), uri, 8192); err != nil {
			t.Fatal("legitimate GET refused", err)
		}
	}
	for _, uri := range []string{acmeplan.Directory, endpoint} {
		if _, _, err := s.get(context.Background(), uri, 8192); err == nil {
			t.Fatal("read replay/unbounded requests")
		}
	}
	if calls != 2 {
		t.Fatal("two-request bound lost")
	}
}

func TestARIProtocolUnsafeDNSAndPreSendRevocationCannotDiscloseID(t *testing.T) {
	now := time.Now().UTC()
	der := ariCertificate(t, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	for _, ips := range [][]netip.Addr{{netip.MustParseAddr("127.0.0.1")}, {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}, nil} {
		deps := dependencies{tls: &tls.Config{MinVersion: tls.VersionTLS12}, lookup: func(context.Context, string, string) ([]netip.Addr, error) { return ips, nil }, dial: func(context.Context, string, string) (net.Conn, error) { t.Error("unsafe DNS dialed"); return nil, nil }}
		if result, err := renewalInformation(context.Background(), func() bool { return true }, deps, der, false); err == nil || !reflect.DeepEqual(result, ariObservation{}) {
			t.Fatal("unsafe DNS disclosed result")
		}
	}
	var calls atomic.Int32
	var permitted atomic.Bool
	permitted.Store(true)
	deps, _ := fakeCA(t, func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
		t.Error("application request sent after revocation")
	})
	dial := deps.dial
	deps.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		permitted.Store(false)
		return conn, err
	}
	if result, err := renewalInformation(context.Background(), permitted.Load, deps, der, false); err == nil || !reflect.DeepEqual(result, ariObservation{}) || calls.Load() != 0 {
		t.Fatal("pre-send revocation ignored")
	}
}

func FuzzStagingARIURI(f *testing.F) {
	f.Add(renewalInfoURL + "/AQID.AIA")
	f.Add("https://error-sentinel.invalid/AQID.AIA")
	f.Fuzz(func(t *testing.T, uri string) {
		if len(uri) > 2048 {
			t.Skip()
		}
		if !validARIURL(uri) {
			return
		}
		if !strings.HasPrefix(uri, renewalInfoURL+"/") || strings.ContainsAny(uri, "?#%\\\r\n") {
			t.Fatal("URI escaped fixed resource")
		}
		id := strings.TrimPrefix(uri, renewalInfoURL+"/")
		parts := strings.Split(id, ".")
		if len(parts) != 2 {
			t.Fatal("wrong ID shape")
		}
		for _, part := range parts {
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(part)
			if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != part {
				t.Fatal("noncanonical ID accepted")
			}
		}
	})
}
