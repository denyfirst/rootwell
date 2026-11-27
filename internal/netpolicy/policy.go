// Package netpolicy says which addresses Rootwell may connect to on a
// person's behalf: a website they check, and the mail server they name for
// alerts (ADR 0090, ADR 0092). It opens no socket.
package netpolicy

import "net/netip"

// Reachable reports whether Rootwell may connect to ip. Public and private
// networks are allowed, so internal servers can be reached. Never allowed:
// this machine (loopback), link-local addresses (where cloud metadata
// services live), multicast, documentation and reserved ranges, and IPv6
// transition ranges that embed an IPv4 address the rules above would refuse.
func Reachable(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range denied {
		if p.Contains(ip) {
			return false
		}
	}
	if ip.Is4() {
		return true
	}
	return netip.MustParsePrefix("2000::/3").Contains(ip) || netip.MustParsePrefix("fc00::/7").Contains(ip)
}

// Ranges that are never a server to reach. Private ranges (10/8, 172.16/12,
// 192.168/16, 100.64/10, fc00::/7) are deliberately absent.
var denied = []netip.Prefix{
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
