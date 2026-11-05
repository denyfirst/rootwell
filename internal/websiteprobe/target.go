package websiteprobe

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

var ErrTarget = errors.New("enter a public DNS name or HTTPS origin on port 443, without a path, credentials or query")

// ParseTarget accepts an origin, never a general fetch URL.
func ParseTarget(input string) (string, error) {
	if input != strings.TrimSpace(input) || input == "" || len(input) > 270 {
		return "", ErrTarget
	}
	value := input
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(input, "#") || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return "", ErrTarget
	}
	host := strings.ToLower(u.Hostname())
	if u.Host != host && !strings.EqualFold(u.Host, host) && !strings.EqualFold(u.Host, host+":443") {
		return "", ErrTarget
	}
	if len(host) > 253 || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") {
		return "", ErrTarget
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", ErrTarget
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrTarget
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return "", ErrTarget
			}
		}
	}
	for _, suffix := range []string{"localhost", "local", "internal", "test", "example", "invalid", "onion", "home.arpa"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return "", ErrTarget
		}
	}
	return host, nil
}

func publicAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() {
		return false
	}
	for _, p := range deniedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return ip.Is4() || netip.MustParsePrefix("2000::/3").Contains(ip)
}

// Conservative special-use exclusions, including mapped IPv4 and IPv6
// transition ranges. Network egress controls remain the operator's boundary.
var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}
