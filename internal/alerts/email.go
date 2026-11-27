package alerts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/netip"
	"net/smtp"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/netpolicy"
)

// Email sends alerts through the person's own mail server, always over TLS:
// TLS from the first byte (usually port 465) or STARTTLS (usually 587). The
// server's certificate must verify against the public roots or a certificate
// authority saved in Certificates, as Website check's does.
type Email struct {
	// Host is the mail server's DNS name or IP address.
	Host string
	Port int
	// Security is "tls" or "starttls".
	Security string
	// Username and Password sign in to the mail server; both may be empty
	// for a server that takes mail from this host without signing in. The
	// password is a secret: sealed in the vault, never shown or logged.
	Username string
	Password string
	From     string
	To       []string
}

var (
	// ErrEmailSettings says a setting is missing or malformed.
	ErrEmailSettings = errors.New("the mail settings are not complete")
	// ErrEmailAddress says the mail server's address may not be reached.
	ErrEmailAddress = errors.New("the mail server is on an address Rootwell does not reach")
	// ErrEmailUnreachable says nothing answered.
	ErrEmailUnreachable = errors.New("the mail server could not be reached")
	// ErrEmailTLS says TLS failed: no STARTTLS, or a certificate that does not
	// verify.
	ErrEmailTLS = errors.New("the mail server's TLS could not be verified")
	// ErrEmailSignIn says the server refused the user name or password.
	ErrEmailSignIn = errors.New("the mail server refused the sign-in")
	// ErrEmailRefused says the server refused the sender, a recipient or the
	// message.
	ErrEmailRefused = errors.New("the mail server refused the message")
)

const maxRecipients = 10

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// plainAddress reads one bare address, such as alerts@example.com.
func plainAddress(value string) bool {
	if value == "" || len(value) > 254 || strings.ContainsAny(value, "\r\n<>\" ,") {
		return false
	}
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value && parsed.Name == ""
}

// Check says whether the settings are complete and well formed, without
// connecting.
func (e Email) Check() error {
	host := strings.ToLower(e.Host)
	if host != e.Host || len(host) == 0 || len(host) > 253 {
		return ErrEmailSettings
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || !netpolicy.Reachable(ip) {
			return ErrEmailAddress
		}
	} else {
		labels := strings.Split(host, ".")
		if len(labels) < 2 || host == "localhost" || strings.HasSuffix(host, ".localhost") {
			return ErrEmailSettings
		}
		for _, label := range labels {
			if !hostLabel.MatchString(label) {
				return ErrEmailSettings
			}
		}
	}
	if e.Port < 1 || e.Port > 65535 || (e.Security != "tls" && e.Security != "starttls") {
		return ErrEmailSettings
	}
	if len(e.Username) > 256 || len(e.Password) > 1024 || (e.Password != "" && e.Username == "") ||
		!utf8.ValidString(e.Username) || strings.ContainsAny(e.Username, "\r\n\x00") || strings.ContainsAny(e.Password, "\r\n\x00") {
		return ErrEmailSettings
	}
	if !plainAddress(e.From) || len(e.To) == 0 || len(e.To) > maxRecipients {
		return ErrEmailSettings
	}
	for _, to := range e.To {
		if !plainAddress(to) {
			return ErrEmailSettings
		}
	}
	return nil
}

// emailSender reaches mail servers. Tests replace the lookup and give the
// roots of a local stand-in.
type emailSender struct {
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	dial   func(ctx context.Context, address string) (net.Conn, error)
}

func newEmailSender() emailSender {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return emailSender{
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		dial: func(ctx context.Context, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address)
		},
	}
}

// address finds where to connect: the host itself when it is an address,
// or its first allowed IPv4 answer, then IPv6. Every answer must be allowed.
func (s emailSender) address(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !netpolicy.Reachable(ip) {
			return netip.Addr{}, ErrEmailAddress
		}
		return ip.Unmap(), nil
	}
	lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	answers, err := s.lookup(lookup, host)
	if err != nil || len(answers) == 0 || len(answers) > 16 {
		return netip.Addr{}, ErrEmailUnreachable
	}
	var chosen netip.Addr
	for _, ip := range answers {
		if !netpolicy.Reachable(ip) {
			return netip.Addr{}, ErrEmailAddress
		}
		ip = ip.Unmap()
		if !chosen.IsValid() || (ip.Is4() && !chosen.Is4()) {
			chosen = ip
		}
	}
	return chosen, nil
}

// send delivers one message to every recipient, or none. roots are the
// public roots and the authorities saved in Certificates.
func (s emailSender) send(ctx context.Context, e Email, roots *x509.CertPool, subject, text string, now time.Time) error {
	if err := e.Check(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	ip, err := s.address(ctx, e.Host)
	if err != nil {
		return err
	}
	conn, err := s.dial(ctx, net.JoinHostPort(ip.String(), strconv.Itoa(e.Port)))
	if err != nil {
		return ErrEmailUnreachable
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	config := &tls.Config{ServerName: e.Host, RootCAs: roots, MinVersion: tls.VersionTLS12}
	if e.Security == "tls" {
		secure := tls.Client(conn, config)
		if secure.HandshakeContext(ctx) != nil {
			return ErrEmailTLS
		}
		conn = secure
	}
	client, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		return ErrEmailUnreachable
	}
	defer client.Close()
	if err := client.Hello("rootwell"); err != nil {
		return ErrEmailUnreachable
	}
	if e.Security == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return ErrEmailTLS
		}
		if client.StartTLS(config) != nil {
			return ErrEmailTLS
		}
	}
	if e.Username != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return ErrEmailSignIn
		}
		// PLAIN, over the TLS made above; net/smtp refuses it otherwise.
		if client.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)) != nil {
			return ErrEmailSignIn
		}
	}
	if client.Mail(e.From) != nil {
		return ErrEmailRefused
	}
	for _, to := range e.To {
		if client.Rcpt(to) != nil {
			return ErrEmailRefused
		}
	}
	body, err := message(e.From, e.To, subject, text, now)
	if err != nil {
		return ErrEmailRefused
	}
	writer, err := client.Data()
	if err != nil {
		return ErrEmailRefused
	}
	if _, err := writer.Write(body); err != nil {
		return ErrEmailRefused
	}
	if writer.Close() != nil {
		return ErrEmailRefused
	}
	_ = client.Quit()
	return nil
}

// message builds a plain-text mail. Every header value is checked or
// encoded, so nothing in a certificate's name can add a header.
func message(from string, to []string, subject, text string, now time.Time) ([]byte, error) {
	if strings.ContainsAny(subject, "\r\n") || !utf8.ValidString(subject) || !utf8.ValidString(text) {
		return nil, ErrEmailRefused
	}
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	header := func(name, value string) { b.WriteString(name + ": " + value + "\r\n") }
	header("From", from)
	header("To", strings.Join(to, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", subject))
	header("Date", now.UTC().Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id[:])+"@rootwell.invalid>")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	header("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	q := quotedprintable.NewWriter(&b)
	if _, err := q.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := q.Close(); err != nil {
		return nil, err
	}
	b.WriteString("\r\n")
	return b.Bytes(), nil
}
