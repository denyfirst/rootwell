// Package servecert makes the certificate Rootwell serves its own pages with
// (ADR 0088). rootwelld creates a local CA on its first start, and
// `rootwelld serving-names` replaces it; its name constraints allow
// only the names this installation answers to, so a stolen CA key cannot sign
// for anything else; the CA signs a short-lived P-256 server certificate that
// rootwelld renews by itself. A browser trusts the CA once, by its printed
// fingerprint. Once public ACME works, an installation may serve a public
// certificate for its own name instead.
package servecert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// ErrRefused hides why a name or certificate was refused.
var ErrRefused = errors.New("serving certificate refused")

const (
	caLifetime     = 10 * 365 * 24 * time.Hour
	serverLifetime = 90 * 24 * time.Hour
	// RenewBefore is how long before expiry rootwelld replaces its certificate.
	RenewBefore = 30 * 24 * time.Hour
	maxNames    = 16
)

// Names are what an installation answers to: DNS names, and IP addresses
// written as literals. "localhost" and the loopback addresses are always
// among them.
type Names struct {
	DNS []string
	IPs []netip.Addr
}

// ParseNames checks the names an operator gave and adds the loopback ones.
func ParseNames(values []string) (Names, error) {
	n := Names{DNS: []string{"localhost"}, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}}
	for _, value := range values {
		if ip, err := netip.ParseAddr(value); err == nil {
			ip = ip.Unmap()
			if ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
				return Names{}, ErrRefused
			}
			if !slices.Contains(n.IPs, ip) {
				n.IPs = append(n.IPs, ip)
			}
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(value, "."))
		if !validDNSName(name) {
			return Names{}, ErrRefused
		}
		if !slices.Contains(n.DNS, name) {
			n.DNS = append(n.DNS, name)
		}
	}
	if len(n.DNS)+len(n.IPs) > maxNames {
		return Names{}, ErrRefused
	}
	return n, nil
}

func validDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.HasPrefix(name, "*") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Authority is the local CA: its certificate and key.
type Authority struct {
	Certificate *x509.Certificate
	Key         *ecdsa.PrivateKey
}

func serial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, ErrRefused
	}
	return n.Add(n, big.NewInt(1)), nil
}

// NewAuthority makes a CA that may sign only for names, and only server
// certificates: it is name-constrained, has path length zero and allows only
// server authentication.
func NewAuthority(names Names, now time.Time) (Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Authority{}, ErrRefused
	}
	number, err := serial()
	if err != nil {
		return Authority{}, err
	}
	template := &x509.Certificate{
		SerialNumber:                number,
		Subject:                     pkix.Name{CommonName: "Rootwell local authority", Organization: []string{"Rootwell"}},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.Add(caLifetime),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         slices.Clone(names.DNS),
	}
	for _, ip := range names.IPs {
		bits := ip.BitLen()
		template.PermittedIPRanges = append(template.PermittedIPRanges, &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(bits, bits)})
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return Authority{}, ErrRefused
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return Authority{}, ErrRefused
	}
	return Authority{Certificate: certificate, Key: key}, nil
}

// Issue signs a new server certificate for exactly names.
func (a Authority) Issue(names Names, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if a.Certificate == nil || a.Key == nil || !now.Before(a.Certificate.NotAfter) {
		return nil, nil, ErrRefused
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, ErrRefused
	}
	number, err := serial()
	if err != nil {
		return nil, nil, err
	}
	notAfter := now.Add(serverLifetime)
	if notAfter.After(a.Certificate.NotAfter) {
		notAfter = a.Certificate.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: number,
		Subject:      pkix.Name{CommonName: names.DNS[0]},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     slices.Clone(names.DNS),
	}
	for _, ip := range names.IPs {
		template.IPAddresses = append(template.IPAddresses, ip.AsSlice())
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.Certificate, &key.PublicKey, a.Key)
	if err != nil {
		return nil, nil, ErrRefused
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, ErrRefused
	}
	return certificate, key, nil
}

// NeedsRenewal reports whether a serving certificate is within RenewBefore of
// its end, or no longer covers names.
func NeedsRenewal(certificate *x509.Certificate, names Names, now time.Time) bool {
	if certificate == nil || !now.Add(RenewBefore).Before(certificate.NotAfter) {
		return true
	}
	if !slices.Equal(certificate.DNSNames, names.DNS) || len(certificate.IPAddresses) != len(names.IPs) {
		return true
	}
	for i, ip := range names.IPs {
		if got, ok := netip.AddrFromSlice(certificate.IPAddresses[i]); !ok || got.Unmap() != ip {
			return true
		}
	}
	return false
}

// Fingerprint is the CA's SHA-256 fingerprint, as a browser shows it.
func Fingerprint(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = strings.ToUpper(hexByte(b))
	}
	return strings.Join(parts, ":")
}

func hexByte(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0x0f]})
}

// Hosts lists each name as a browser writes it in the Host header, with port,
// and says whether it is a loopback name.
func (n Names) Hosts(port string) map[string]bool {
	hosts := make(map[string]bool, len(n.DNS)+len(n.IPs))
	for _, name := range n.DNS {
		hosts[net.JoinHostPort(name, port)] = name == "localhost"
	}
	for _, ip := range n.IPs {
		hosts[net.JoinHostPort(ip.String(), port)] = ip.IsLoopback()
	}
	return hosts
}
