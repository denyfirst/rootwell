// Package cloudflareconfig checks local credential syntax, not provider access
// or token permissions. It has no network, persistence or secret export API.
package cloudflareconfig

import "github.com/denyfirst/rootwell/internal/acmeplan"

func Valid(zoneID, zoneName string, token []byte) bool {
	if len(zoneID) != 32 || len(token) < 40 || len(token) > 256 {
		return false
	}
	for _, c := range zoneID {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	plan, err := acmeplan.Check(acmeplan.Provider, "dns-01", []string{zoneName})
	if err != nil || len(plan.Domains) != 1 || plan.Domains[0] != zoneName || zoneName[0] == '*' {
		return false
	}
	for _, c := range token {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
