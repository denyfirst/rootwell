package websiteprobe

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/denyfirst/rootwell/internal/netpolicy"
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

// allowedAddress reports whether a check may connect to ip: the policy
// alerts share (internal/netpolicy, ADR 0090).
func allowedAddress(ip netip.Addr) bool { return netpolicy.Reachable(ip) }
