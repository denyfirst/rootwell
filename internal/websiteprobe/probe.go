// Package websiteprobe is an explicit, authenticated-caller-only TLS
// diagnostic capability. It never sends HTTP or fetches certificate URLs.
package websiteprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/denyfirst/rootwell/internal/websitechain"
)

var (
	ErrUnavailable = errors.New("website connections require Linux or Linux Docker; native preview stays offline")
	ErrBlocked     = errors.New("destination refused: Rootwell does not connect to its own machine, link-local, reserved or metadata addresses")
	ErrNotFound    = errors.New("the name was not found in DNS")
	ErrDNS         = errors.New("DNS did not answer")
	ErrRefused     = errors.New("nothing answers on this port")
	ErrTimeout     = errors.New("no answer in time")
	ErrNotTLS      = errors.New("the server answered, but not with TLS")
	ErrHandshake   = errors.New("the server did not finish a secure connection")
	ErrConnection  = errors.New("TLS observation could not complete; no certificate trust result is available")
	ErrTrustStore  = errors.New("server trust store is unavailable; no trust result is available")
)

// Failure carries the address a failed check reached, when it reached one.
type Failure struct {
	Err     error
	Address string
}

func (f *Failure) Error() string { return f.Err.Error() }
func (f *Failure) Unwrap() error { return f.Err }

// Timeout bounds one whole check: lookup, up to three connections and their
// handshakes.
const Timeout = 15 * time.Second

const (
	dialTimeout      = 3 * time.Second
	handshakeTimeout = 5 * time.Second
	maxAddresses     = 16
)

type dependencies struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	roots  func() (*x509.CertPool, error)
	now    func() time.Time
}

// Available excludes native verifiers with ambient AIA/root network access.
func Available() bool { return runtime.GOOS == "linux" }

// Probe looks the name up once and connects only to the checked numeric
// addresses: at most one IPv4 and one IPv6 address, and one more attempt with
// classic key exchange. The caller owns authorization, concurrency and rate
// limits. saved are roots the person saved in Certificates.
func Probe(ctx context.Context, target Target, saved []*x509.Certificate, permit func() bool) (websitechain.Report, error) {
	if !Available() {
		return websitechain.Report{}, ErrUnavailable
	}
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: -1}
	return probe(ctx, target, saved, permit, dependencies{net.DefaultResolver.LookupNetIP, dialer.DialContext, x509.SystemCertPool, time.Now})
}

func probe(ctx context.Context, target Target, saved []*x509.Certificate, permit func() bool, deps dependencies) (websitechain.Report, error) {
	if canonical, err := ParseTarget(target.String()); err != nil || canonical != target {
		return websitechain.Report{}, ErrTarget
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	allowed := func() bool { return ctx.Err() == nil && permit != nil && permit() }
	if !allowed() {
		return websitechain.Report{}, ErrConnection
	}
	roots, err := deps.roots()
	if err != nil || roots == nil || roots.Equal(x509.NewCertPool()) {
		return websitechain.Report{}, ErrTrustStore
	}
	if !allowed() {
		return websitechain.Report{}, ErrConnection
	}
	var addresses []netip.Addr
	if target.IsAddress() {
		addresses = []netip.Addr{netip.MustParseAddr(target.Host)}
	} else {
		addresses, err = deps.lookup(ctx, "ip", target.Host)
		var dnsErr *net.DNSError
		switch {
		case err != nil && errors.As(err, &dnsErr) && dnsErr.IsNotFound:
			return websitechain.Report{}, ErrNotFound
		case err != nil:
			return websitechain.Report{}, ErrDNS
		case len(addresses) == 0:
			return websitechain.Report{}, ErrNotFound
		case len(addresses) > maxAddresses:
			return websitechain.Report{}, ErrBlocked
		}
	}
	// Every answer must be allowed: a name that also points at a refused
	// address is refused as a whole.
	for _, ip := range addresses {
		if !allowedAddress(ip) {
			return websitechain.Report{}, ErrBlocked
		}
	}
	// IPv4 first: container networks often have no IPv6 route.
	var candidates []netip.Addr
	for _, want4 := range []bool{true, false} {
		for _, ip := range addresses {
			if ip = ip.Unmap(); ip.Is4() == want4 {
				candidates = append(candidates, ip)
				break
			}
		}
	}
	var last error = ErrConnection
	lastAddress := ""
	retried := false // one classic attempt per check, so at most three connections
	for _, ip := range candidates {
		if !allowed() {
			return websitechain.Report{}, ErrConnection
		}
		address := ip.String()
		r, err := observe(ctx, deps, target, address, roots, saved, allowed, false)
		if err == nil {
			return r, nil
		}
		if errors.Is(err, errClassicMayHelp) && !retried {
			retried = true
			r, retryErr := observe(ctx, deps, target, address, roots, saved, allowed, true)
			if retryErr == nil {
				r.Findings = append(r.Findings, websitechain.Finding{Code: "classic-key-exchange", Level: "note",
					Title:        "The first connection failed; a second one without post-quantum key exchange worked",
					Detail:       "Current browsers greet a server with a larger message for post-quantum key exchange. This server, a firewall or load balancer in front of it, or the network between Rootwell and the server dropped that message.",
					Action:       "If visitors with current browsers cannot connect, update the firewall or load balancer in front of this server.",
					Certificates: []string{}})
				return r, nil
			}
			err = retryErr
		}
		if errors.Is(err, errUnauthorized) {
			return websitechain.Report{}, ErrConnection
		}
		last, lastAddress = err, address
		if !errors.Is(err, ErrRefused) && !errors.Is(err, ErrTimeout) {
			break // the server answered; another address would not say more
		}
	}
	if errors.Is(last, errClassicMayHelp) {
		last = ErrHandshake
	}
	return websitechain.Report{}, &Failure{Err: last, Address: lastAddress}
}

var (
	errClassicMayHelp = errors.New("connection dropped during the greeting")
	errUnauthorized   = errors.New("check no longer authorized")
)

// observe makes one connection and one handshake to a numeric address, with
// the target name as SNI when it is a name. classic leaves out post-quantum
// key exchange.
func observe(ctx context.Context, deps dependencies, target Target, address string, roots *x509.CertPool, saved []*x509.Certificate, allowed func() bool, classic bool) (websitechain.Report, error) {
	conn, err := deps.dial(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(target.Port)))
	if err != nil || conn == nil {
		if conn != nil {
			_ = conn.Close()
		}
		if !allowed() {
			return websitechain.Report{}, errUnauthorized
		}
		return websitechain.Report{}, dialFailure(err)
	}
	defer conn.Close()
	if !allowed() {
		return websitechain.Report{}, errUnauthorized
	}
	deadline, _ := ctx.Deadline()
	if limit := time.Now().Add(handshakeTimeout); limit.Before(deadline) {
		deadline = limit
	}
	if conn.SetDeadline(deadline) != nil {
		return websitechain.Report{}, ErrConnection
	}
	// Interrupt blocked reads promptly on request cancellation. HandshakeContext
	// also cancels; this covers socket operations below and never outlives conn.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	bounded := &boundedConn{Conn: conn, remainingRead: 256 << 10, remainingWrite: 64 << 10}
	var observed []*x509.Certificate
	config := &tls.Config{
		MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true,
		// Diagnostic capture only. No application data or secrets are sent.
		// Trust/hostname/usage/signatures are checked separately by Analyze;
		// an untrusted peer must remain observable, never implicitly trusted.
		InsecureSkipVerify: true, // #nosec G402 -- deliberately observe invalid chains, independently verified below
		VerifyConnection: func(state tls.ConnectionState) error {
			if !allowed() || len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > websitechain.MaxCertificates {
				return ErrConnection
			}
			size := 0
			for _, c := range state.PeerCertificates {
				if c == nil || len(c.Raw) > websitechain.MaxCertificateBytes-size {
					return ErrConnection
				}
				size += len(c.Raw)
			}
			observed = state.PeerCertificates
			return nil
		},
	}
	if !target.IsAddress() {
		config.ServerName = target.Host
	}
	if classic {
		config.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	}
	secure := tls.Client(bounded, config)
	handshakeErr := secure.HandshakeContext(ctx)
	if !allowed() {
		return websitechain.Report{}, errUnauthorized
	}
	if handshakeErr != nil && observed == nil {
		return websitechain.Report{}, handshakeFailure(handshakeErr)
	}
	state := secure.ConnectionState()
	// Close the raw socket: no application request, session reuse or TLS
	// shutdown exchange. The certificates are the entire observation.
	_ = conn.Close()
	// A certificate sent twice is analyzed once and named.
	var unique, repeated []*x509.Certificate
	for _, c := range observed {
		if containsCertificate(unique, c) {
			repeated = append(repeated, c)
		} else {
			unique = append(unique, c)
		}
	}
	r, err := websitechain.AnalyzeWithSaved(unique, roots, saved, target.Host, deps.now().UTC())
	if err != nil || !allowed() {
		return websitechain.Report{}, errUnauthorized
	}
	r.Address, r.Port = address, target.Port
	if len(repeated) > 0 {
		r.Findings = append(r.Findings, websitechain.Finding{Code: "repeated", Level: "attention",
			Title:        "The server sends the same certificate more than once",
			Detail:       "Each certificate is needed once. Some apps refuse a chain with repeats.",
			Action:       "Remove the repeated certificate from the server's certificate file.",
			Certificates: []string{}})
		if r.State == "verified" {
			r.State = "attention"
		}
	}
	switch {
	case handshakeErr != nil:
		r.TLS = ""
		r.Findings = append(r.Findings, websitechain.Finding{Code: "handshake-incomplete", Level: "note",
			Title:        "The server stopped after sending its certificates",
			Detail:       "The certificates below were received, but the server ended the connection before it finished. It may ask visitors for a client certificate.",
			Action:       "",
			Certificates: []string{}})
	case state.Version == tls.VersionTLS13:
		r.TLS = "TLS 1.3"
	default:
		r.TLS = "TLS 1.2"
	}
	return r, nil
}

func containsCertificate(list []*x509.Certificate, c *x509.Certificate) bool {
	for _, l := range list {
		if l.Equal(c) {
			return true
		}
	}
	return false
}

func dialFailure(err error) error {
	var netErr net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return ErrRefused
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		return ErrTimeout
	case errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH):
		return ErrTimeout
	}
	return ErrConnection
}

func handshakeFailure(err error) error {
	var header tls.RecordHeaderError
	var op *net.OpError
	switch {
	case errors.As(err, &header):
		return ErrNotTLS
	case errors.As(err, &op) && op.Op == "remote error":
		return ErrHandshake // the server sent a TLS alert
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE):
		return errClassicMayHelp
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded):
		return errClassicMayHelp
	}
	return ErrHandshake
}

type boundedConn struct {
	net.Conn
	remainingRead, remainingWrite int
}

func (c *boundedConn) Read(p []byte) (int, error) {
	if c.remainingRead <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if len(p) > c.remainingRead {
		p = p[:c.remainingRead]
	}
	n, err := c.Conn.Read(p)
	c.remainingRead -= n
	return n, err
}

func (c *boundedConn) Write(p []byte) (int, error) {
	if len(p) > c.remainingWrite {
		return 0, io.ErrShortWrite
	}
	n, err := c.Conn.Write(p)
	c.remainingWrite -= n
	return n, err
}
