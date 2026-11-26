package websiteprobe

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

var ErrTarget = errors.New("enter a website name or address, with a port if it is not 443; no path, user name or query")

// Target is one TLS endpoint: a DNS name or an IP address, and a port.
type Target struct {
	Host string // lower-case DNS name, or an IP address without brackets
	Port int
}

// String is the canonical form: the port only when it is not 443, and IPv6
// addresses in brackets.
func (t Target) String() string {
	host := t.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if t.Port == 443 {
		return host
	}
	return host + ":" + strconv.Itoa(t.Port)
}

// IsAddress reports whether the target names an IP address, not a DNS name.
func (t Target) IsAddress() bool {
	_, err := netip.ParseAddr(t.Host)
	return err == nil
}

// ParseTarget accepts an origin, never a general fetch URL: a DNS name or IP
// address, an optional port, and an optional https:// in front. Internal
// names and private addresses are accepted here; which addresses may be
// dialed is decided after the lookup.
func ParseTarget(input string) (Target, error) {
	if input != strings.TrimSpace(input) || input == "" || len(input) > 280 {
		return Target{}, ErrTarget
	}
	value := input
	if !strings.Contains(value, "://") {
		// A bare IPv6 address has colons but no port.
		if a, err := netip.ParseAddr(value); err == nil && a.Is6() {
			value = "[" + value + "]"
		}
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(input, "#") || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return Target{}, ErrTarget
	}
	host := strings.ToLower(u.Hostname())
	port := 443
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || p[0] == '0' {
			return Target{}, ErrTarget
		}
		port = n
	} else if strings.HasSuffix(u.Host, ":") {
		return Target{}, ErrTarget
	}
	if a, err := netip.ParseAddr(host); err == nil {
		// Literal addresses only: no zones, no IPv4 inside IPv6 spelling.
		if a.Zone() != "" || (a.Is4In6()) || (a.Is6() && !strings.HasPrefix(u.Host, "[")) {
			return Target{}, ErrTarget
		}
		if a.Is6() && strings.Contains(host, ".") {
			return Target{}, ErrTarget
		}
		return Target{a.String(), port}, nil
	}
	if strings.HasPrefix(u.Host, "[") {
		return Target{}, ErrTarget
	}
	if len(host) > 253 || strings.HasSuffix(host, ".") || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return Target{}, ErrTarget
	}
	allDigits := true
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return Target{}, ErrTarget
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return Target{}, ErrTarget
			}
			if c < '0' || c > '9' {
				allDigits = false
			}
		}
	}
	// "10.1" or "3232235777" are numbers some resolvers read as addresses.
	if allDigits {
		return Target{}, ErrTarget
	}
	return Target{host, port}, nil
}

// allowedAddress reports whether a check may connect to ip. Public and
// private networks are allowed, so internal servers can be checked. Never
// allowed: this machine (loopback), link-local addresses (where cloud metadata
// services live), multicast, documentation and reserved ranges, and IPv6
// transition ranges that embed an IPv4 address the rules above would refuse.
func allowedAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range deniedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	if ip.Is4() {
		return true
	}
	return netip.MustParsePrefix("2000::/3").Contains(ip) || netip.MustParsePrefix("fc00::/7").Contains(ip)
}

// Ranges that are never a server to check. Private ranges (10/8, 172.16/12,
// 192.168/16, 100.64/10, fc00::/7) are deliberately absent.
var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	// Cloud metadata services outside link-local.
	netip.MustParsePrefix("100.100.100.200/32"), netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
}
