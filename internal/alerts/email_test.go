package alerts

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

const mailHost = "mail.rootwell.test"

// authority makes a CA and a server certificate for mailHost under it.
func authority(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test mail CA"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: mailHost},
		DNSNames: []string{mailHost}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fakeMail is just enough of a mail server: TLS or STARTTLS, AUTH PLAIN
// after TLS only, and one message.
type fakeMail struct {
	listener  net.Listener
	cert      tls.Certificate
	implicit  bool
	starttls  bool
	user      string
	password  string
	refuseTo  string
	mu        sync.Mutex
	commands  []string
	data      string
	sawPlain  bool
	delivered bool
}

func (f *fakeMail) serve() {
	conn, err := f.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if f.implicit {
		conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{f.cert}})
	}
	secure := f.implicit
	r := bufio.NewReader(conn)
	say := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	say("220 " + mailHost + " ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		f.mu.Lock()
		f.commands = append(f.commands, line)
		f.mu.Unlock()
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch {
		case verb == "EHLO" || verb == "HELO":
			extensions := []string{mailHost}
			if f.starttls && !secure {
				extensions = append(extensions, "STARTTLS")
			}
			if secure {
				extensions = append(extensions, "AUTH PLAIN")
			}
			for i, e := range extensions {
				sep := "-"
				if i == len(extensions)-1 {
					sep = " "
				}
				say("250" + sep + e)
			}
		case verb == "STARTTLS":
			say("220 go ahead")
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{f.cert}})
			if tlsConn.Handshake() != nil {
				return
			}
			conn, secure = tlsConn, true
			r = bufio.NewReader(conn)
		case verb == "AUTH":
			if !secure {
				f.sawPlain = true
				say("538 encryption required")
				continue
			}
			parts := strings.Fields(line)
			raw, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			fields := strings.Split(string(raw), "\x00")
			if len(fields) == 3 && fields[1] == f.user && fields[2] == f.password {
				say("235 ok")
			} else {
				say("535 no")
			}
		case verb == "MAIL":
			say("250 ok")
		case verb == "RCPT":
			if f.refuseTo != "" && strings.Contains(line, f.refuseTo) {
				say("550 no such user")
			} else {
				say("250 ok")
			}
		case verb == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data, f.delivered = b.String(), true
			f.mu.Unlock()
			say("250 queued")
		case verb == "QUIT":
			say("221 bye")
			return
		default:
			say("502 what")
		}
	}
}

func startMail(t *testing.T, f *fakeMail) emailSender {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.listener = l
	t.Cleanup(func() { _ = l.Close() })
	go f.serve()
	// The name resolves to an ordinary private address; the test dials the
	// stand-in wherever the sender meant to go.
	return emailSender{
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.20.30.40")}, nil
		},
		dial: func(ctx context.Context, address string) (net.Conn, error) {
			if address != "10.20.30.40:587" && address != "10.20.30.40:465" {
				return nil, errors.New("dialed " + address)
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
		},
	}
}

func settings(security string, port int) Email {
	return Email{Host: mailHost, Port: port, Security: security, Username: "alerts", Password: "a mail password", From: "rootwell@rootwell.test", To: []string{"ops@rootwell.test", "web@rootwell.test"}}
}

func TestEmailGoesOnlyOverVerifiedTLS(t *testing.T) {
	roots, cert := authority(t)
	now := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		security string
		port     int
		implicit bool
	}{{"starttls", "starttls", 587, false}, {"tls", "tls", 465, true}} {
		f := &fakeMail{cert: cert, implicit: tc.implicit, starttls: !tc.implicit, user: "alerts", password: "a mail password"}
		s := startMail(t, f)
		if err := s.send(context.Background(), settings(tc.security, tc.port), roots, "Rootwell: bakı.test ends in 7 days", "bakı.test ends on 4 Dec 2026.\nUsed on: web-1", now); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		f.mu.Lock()
		data, commands := f.data, strings.Join(f.commands, "\n")
		f.mu.Unlock()
		if !strings.Contains(data, "Subject: =?utf-8?q?Rootwell:_bak=C4=B1.test_ends_in_7_days?=\r\n") ||
			!strings.Contains(data, "To: ops@rootwell.test, web@rootwell.test\r\n") || !strings.Contains(data, "Auto-Submitted: auto-generated\r\n") ||
			!strings.Contains(data, "bak=C4=B1.test ends on 4 Dec 2026.\r\nUsed on: web-1") {
			t.Fatalf("%s: the message reads\n%s", tc.name, data)
		}
		if !strings.Contains(commands, "RCPT TO:<web@rootwell.test>") || f.sawPlain {
			t.Fatalf("%s: the conversation was\n%s", tc.name, commands)
		}
	}
}

func TestEmailRefusesWhatItCannotVerify(t *testing.T) {
	roots, cert := authority(t)
	otherRoots, _ := authority(t)
	now := time.Now()
	cases := []struct {
		name  string
		f     *fakeMail
		e     Email
		roots *x509.CertPool
		want  error
	}{
		{"no STARTTLS offered", &fakeMail{cert: cert, user: "alerts", password: "a mail password"}, settings("starttls", 587), roots, ErrEmailTLS},
		{"an unknown authority", &fakeMail{cert: cert, starttls: true, user: "alerts", password: "a mail password"}, settings("starttls", 587), otherRoots, ErrEmailTLS},
		{"implicit TLS, unknown authority", &fakeMail{cert: cert, implicit: true}, settings("tls", 465), otherRoots, ErrEmailTLS},
		{"a wrong password", &fakeMail{cert: cert, starttls: true, user: "alerts", password: "another"}, settings("starttls", 587), roots, ErrEmailSignIn},
		{"a refused recipient", &fakeMail{cert: cert, starttls: true, user: "alerts", password: "a mail password", refuseTo: "web@"}, settings("starttls", 587), roots, ErrEmailRefused},
	}
	for _, tc := range cases {
		s := startMail(t, tc.f)
		err := s.send(context.Background(), tc.e, tc.roots, "Rootwell test", "x", now)
		if !errors.Is(err, tc.want) || strings.Contains(err.Error(), "a mail password") {
			t.Fatalf("%s: %v", tc.name, err)
		}
		tc.f.mu.Lock()
		delivered, commands := tc.f.delivered, strings.Join(tc.f.commands, "\n")
		tc.f.mu.Unlock()
		if delivered || (tc.want == ErrEmailTLS && strings.Contains(commands, "MAIL")) || strings.Contains(commands, "AUTH") && tc.want == ErrEmailTLS {
			t.Fatalf("%s: went on after the refusal:\n%s", tc.name, commands)
		}
	}
}

func TestEmailReachesOnlyAllowedAddresses(t *testing.T) {
	roots, _ := authority(t)
	for _, answer := range []string{"127.0.0.1", "169.254.169.254", "::1", "fe80::1", "100.100.100.200", "0.0.0.0"} {
		dialed := false
		s := emailSender{
			lookup: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr(answer)}, nil
			},
			dial: func(context.Context, string) (net.Conn, error) { dialed = true; return nil, errors.New("no") },
		}
		if err := s.send(context.Background(), settings("starttls", 587), roots, "x", "x", time.Now()); !errors.Is(err, ErrEmailAddress) || dialed {
			t.Fatalf("%s: %v, dialed %v", answer, err, dialed)
		}
	}
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "[::1]", "::1"} {
		e := settings("starttls", 587)
		e.Host = host
		if err := e.Check(); err == nil {
			t.Fatalf("%s was accepted", host)
		}
	}
}

func TestEmailSettingsAreCheckedBeforeConnecting(t *testing.T) {
	good := settings("starttls", 587)
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
	ip := good
	ip.Host = "10.0.0.25"
	if err := ip.Check(); err != nil {
		t.Fatalf("a private address: %v", err)
	}
	noAuth := good
	noAuth.Username, noAuth.Password = "", ""
	if err := noAuth.Check(); err != nil {
		t.Fatalf("no sign-in: %v", err)
	}
	change := func(f func(*Email)) Email { e := good; e.To = append([]string{}, good.To...); f(&e); return e }
	for name, e := range map[string]Email{
		"one-word host":          change(func(e *Email) { e.Host = "mail" }),
		"localhost":              change(func(e *Email) { e.Host = "localhost" }),
		"upper case host":        change(func(e *Email) { e.Host = "Mail.rootwell.test" }),
		"host with a path":       change(func(e *Email) { e.Host = "mail.rootwell.test/x" }),
		"port 0":                 change(func(e *Email) { e.Port = 0 }),
		"no TLS":                 change(func(e *Email) { e.Security = "none" }),
		"password, no user":      change(func(e *Email) { e.Username = "" }),
		"a header in the from":   change(func(e *Email) { e.From = "rootwell@rootwell.test\r\nBcc: x@evil.invalid" }),
		"a name in the from":     change(func(e *Email) { e.From = "Rootwell <rootwell@rootwell.test>" }),
		"two in one recipient":   change(func(e *Email) { e.To = []string{"a@rootwell.test, b@rootwell.test"} }),
		"no recipient":           change(func(e *Email) { e.To = nil }),
		"eleven recipients":      change(func(e *Email) { e.To = strings.Split(strings.Repeat("a@rootwell.test ", 11), " ")[:11] }),
		"a line in the user":     change(func(e *Email) { e.Username = "alerts\r\nRSET" }),
		"a line in the password": change(func(e *Email) { e.Password = "x\r\nQUIT" }),
	} {
		if err := e.Check(); !errors.Is(err, ErrEmailSettings) && !errors.Is(err, ErrEmailAddress) {
			t.Fatalf("%s was accepted: %v", name, err)
		}
	}
	if _, err := message("a@rootwell.test", []string{"b@rootwell.test"}, "two\r\nBcc: x@evil.invalid", "x", time.Now()); err == nil {
		t.Fatal("a subject added a header")
	}
}
