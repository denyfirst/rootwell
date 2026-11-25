package servecert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func TestNamesAlwaysIncludeLoopbackAndRefuseBadInput(t *testing.T) {
	names, err := ParseNames([]string{"Rootwell.Example.COM.", "192.0.2.10", "::ffff:198.51.100.7", "rootwell.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names.DNS, []string{"localhost", "rootwell.example.com"}) {
		t.Fatalf("dns %v", names.DNS)
	}
	want := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback(), netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.7")}
	if !slices.Equal(names.IPs, want) {
		t.Fatalf("ips %v", names.IPs)
	}
	for _, bad := range [][]string{{"*.example.com"}, {"exa mple.com"}, {"-bad.example"}, {"bad-.example"}, {"a..b"},
		{"fe80::1%eth0"}, {"0.0.0.0"}, {"::"}, {"224.0.0.1"}, {strings.Repeat("a", 64) + ".example"}, {"ünicode.example"},
		{"lan"}, {"com."}, {"rootwell"},
		{"a1.x", "a2.x", "a3.x", "a4.x", "a5.x", "a6.x", "a7.x", "a8.x", "a9.x", "a10.x", "a11.x", "a12.x", "a13.x", "a14.x", "a15.x"}} {
		if _, err := ParseNames(bad); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}

func authority(t *testing.T, values ...string) (Authority, Names) {
	t.Helper()
	names, err := ParseNames(values)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAuthority(names, now)
	if err != nil {
		t.Fatal(err)
	}
	return a, names
}

func TestTheServerCertificateVerifiesForEveryNameAndNothingElse(t *testing.T) {
	a, names := authority(t, "rootwell.example.com", "192.0.2.10")
	certificate, key, err := a.Issue(names, now)
	if err != nil {
		t.Fatal(err)
	}
	if key.Curve != elliptic.P256() || certificate.NotAfter.Sub(now) > 90*24*time.Hour ||
		!slices.Equal(certificate.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) || certificate.IsCA {
		t.Fatal("the server certificate is not a 90-day P-256 server-only leaf")
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.Certificate)
	for _, name := range []string{"localhost", "rootwell.example.com", "127.0.0.1", "::1", "192.0.2.10"} {
		if _, err := certificate.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, CurrentTime: now}); err != nil {
			t.Errorf("%s did not verify: %v", name, err)
		}
	}
	for _, name := range []string{"other.example.com", "192.0.2.11", "example.com"} {
		if _, err := certificate.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, CurrentTime: now}); err == nil {
			t.Errorf("%s verified", name)
		}
	}
}

// A stolen CA key still cannot vouch for another site: the name constraints
// are in the CA certificate the browser trusts.
func TestTheAuthorityCannotSignForOtherNames(t *testing.T) {
	a, _ := authority(t, "rootwell.example.com", "192.0.2.10")
	if !a.Certificate.PermittedDNSDomainsCritical || !a.Certificate.MaxPathLenZero || a.Certificate.MaxPathLen != 0 {
		t.Fatal("the authority is not constrained")
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.Certificate)
	for _, forged := range []struct {
		dns []string
		ips []net.IP
		ask string
	}{{dns: []string{"bank.example"}, ask: "bank.example"}, {ips: []net.IP{net.ParseIP("203.0.113.5")}, ask: "203.0.113.5"},
		{dns: []string{"mail.rootwell.example.com"}, ask: "mail.rootwell.example.com"}, {dns: []string{"a.localhost"}, ask: "a.localhost"}} {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "forged"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: forged.dns, IPAddresses: forged.ips,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, template, a.Certificate, &key.PublicKey, a.Key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: forged.ask, Roots: roots, CurrentTime: now}); err == nil {
			t.Errorf("a certificate for %s signed by the CA key verified", forged.ask)
		}
	}
}

func TestRenewalIsDueBeforeTheEndOrWhenNamesChange(t *testing.T) {
	a, names := authority(t, "rootwell.example.com")
	certificate, _, err := a.Issue(names, now)
	if err != nil {
		t.Fatal(err)
	}
	if NeedsRenewal(certificate, names, now) {
		t.Fatal("a fresh certificate needs renewal")
	}
	if !NeedsRenewal(certificate, names, now.Add(61*24*time.Hour)) {
		t.Fatal("a certificate 29 days from its end does not need renewal")
	}
	more, _ := ParseNames([]string{"rootwell.example.com", "rootwell.lan"})
	if !NeedsRenewal(certificate, more, now) || !NeedsRenewal(nil, names, now) {
		t.Fatal("a certificate for other names, or none, does not need renewal")
	}
	if _, _, err := a.Issue(names, a.Certificate.NotAfter.Add(time.Second)); err == nil {
		t.Fatal("an expired authority issued")
	}
}

func TestTheFingerprintReadsLikeABrowserShowsIt(t *testing.T) {
	a, _ := authority(t)
	fingerprint := Fingerprint(a.Certificate)
	if len(fingerprint) != 95 || strings.Count(fingerprint, ":") != 31 || strings.ToUpper(fingerprint) != fingerprint {
		t.Fatalf("fingerprint %q", fingerprint)
	}
}

// The architecture test lets this file import net for IPNet values only.
func TestThePackageOpensNoSocket(t *testing.T) {
	source, err := os.ReadFile("servecert.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{"Dial", "Listen", "Lookup", "Resolver", "http."} {
		if strings.Contains(string(source), call) {
			t.Errorf("servecert.go uses %s", call)
		}
	}
}

// A name with another of the installation's names below it keeps its
// subdomains open, or the CA could not sign for the name below.
func TestANameBelowAnotherStillVerifies(t *testing.T) {
	a, names := authority(t, "example.lan", "rootwell.example.lan")
	if !slices.Equal(a.Certificate.ExcludedDNSDomains, []string{".localhost", ".rootwell.example.lan"}) {
		t.Fatalf("excluded %v", a.Certificate.ExcludedDNSDomains)
	}
	certificate, _, err := a.Issue(names, now)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.Certificate)
	for _, name := range []string{"example.lan", "rootwell.example.lan"} {
		if _, err := certificate.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, CurrentTime: now}); err != nil {
			t.Errorf("%s did not verify: %v", name, err)
		}
	}
}
