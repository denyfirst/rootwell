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
	"runtime"
	"time"

	"github.com/denyfirst/rootwell/internal/websitechain"
)

var (
	ErrUnavailable = errors.New("website connections require Linux or Linux Docker; native preview stays offline")
	ErrBlocked     = errors.New("destination refused: all DNS answers must be public addresses")
	ErrConnection  = errors.New("TLS observation could not complete; no certificate trust result is available")
	ErrTrustStore  = errors.New("server trust store is unavailable; no trust result is available")
)

type dependencies struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	roots  func() (*x509.CertPool, error)
	now    func() time.Time
}

// Available excludes native verifiers with ambient AIA/root network access.
func Available() bool { return runtime.GOOS == "linux" }

// Probe resolves once and performs at most one numeric-address TLS handshake.
// The caller owns authorization, global concurrency and rate limits.
func Probe(ctx context.Context, input string, permit func() bool) (websitechain.Report, error) {
	if !Available() {
		return websitechain.Report{}, ErrUnavailable
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
	return probe(ctx, input, permit, dependencies{net.DefaultResolver.LookupNetIP, dialer.DialContext, x509.SystemCertPool, time.Now})
}

func probe(ctx context.Context, input string, permit func() bool, deps dependencies) (websitechain.Report, error) {
	host, err := ParseTarget(input)
	if err != nil {
		return websitechain.Report{}, ErrTarget
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
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
	addresses, err := deps.lookup(ctx, "ip", host)
	if err != nil || len(addresses) == 0 || len(addresses) > 16 {
		return websitechain.Report{}, ErrBlocked
	}
	for _, ip := range addresses {
		if !publicAddress(ip) {
			return websitechain.Report{}, ErrBlocked
		}
	}
	if !allowed() {
		return websitechain.Report{}, ErrConnection
	}
	address := addresses[0].Unmap().String()
	conn, err := deps.dial(ctx, "tcp", net.JoinHostPort(address, "443"))
	if err != nil || conn == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return websitechain.Report{}, ErrConnection
	}
	defer conn.Close()
	if !allowed() {
		return websitechain.Report{}, ErrConnection
	}
	deadline, _ := ctx.Deadline()
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
		MinVersion: tls.VersionTLS12, ServerName: host, SessionTicketsDisabled: true,
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
	secure := tls.Client(bounded, config)
	if secure.HandshakeContext(ctx) != nil || !allowed() {
		return websitechain.Report{}, ErrConnection
	}
	state := secure.ConnectionState()
	// Close the raw socket: no application request, session reuse or TLS
	// shutdown exchange. The completed handshake is the entire observation.
	_ = conn.Close()
	r, err := websitechain.Analyze(observed, roots, host, deps.now().UTC())
	if err != nil || !allowed() {
		return websitechain.Report{}, ErrConnection
	}
	r.Address = address
	r.TLS = "TLS 1.2"
	if state.Version == tls.VersionTLS13 {
		r.TLS = "TLS 1.3"
	}
	return r, nil
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
