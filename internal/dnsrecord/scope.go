// Package dnsrecord contains only bounded protocol values. These are untrusted
// observations, not capabilities; the encrypted store supplies their authority.
package dnsrecord

type Scope struct {
	ZoneID, ZoneName, Name, Value, Owner string
}

type State struct{ State, ID string }
