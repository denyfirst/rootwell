// Package acmeprofile describes two fixed ACME environments. It cannot connect,
// select trust, derive keys, migrate accounts or grant provider authority.
package acmeprofile

import (
	"errors"
	"strings"
)

// Profiles are immutable constants, not a process-global mode or URL setting.
// Every method refuses zero/unknown values; callers must bind a chosen profile
// to authenticated custody before a future connector may consume it.
type Profile uint8

const (
	Staging    Profile = 1
	Production Profile = 2
)

var ErrInvalid = errors.New("ACME profile is invalid or unsupported")

func Parse(value string) (Profile, error) {
	switch value {
	case "letsencrypt-staging":
		return Staging, nil
	case "letsencrypt-production":
		return Production, nil
	}
	return 0, ErrInvalid
}
func (p Profile) Valid() bool { return p == Staging || p == Production }
func (p Profile) Provider() string {
	switch p {
	case Staging:
		return "letsencrypt-staging"
	case Production:
		return "letsencrypt-production"
	}
	return ""
}
func (p Profile) Host() string {
	switch p {
	case Staging:
		return "acme-staging-v02.api.letsencrypt.org"
	case Production:
		return "acme-v02.api.letsencrypt.org"
	}
	return ""
}
func (p Profile) Origin() string {
	if !p.Valid() {
		return ""
	}
	return "https://" + p.Host()
}
func (p Profile) Directory() string {
	if !p.Valid() {
		return ""
	}
	return p.Origin() + "/directory"
}
func (p Profile) Namespace() string {
	if !p.Valid() {
		return ""
	}
	return "rootwell.acme-profile." + p.Provider() + ".v1"
}
func (p Profile) TestOnly() bool { return p == Staging }

func positive(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] == '0' {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func (p Profile) AccountURL(value string) bool {
	if !p.Valid() {
		return false
	}
	prefix := p.Origin() + "/acme/acct/"
	return strings.HasPrefix(value, prefix) && positive(strings.TrimPrefix(value, prefix))
}
func (p Profile) OrderURL(value, account string) bool {
	if !p.AccountURL(account) {
		return false
	}
	prefix := p.Origin() + "/acme/order/" + strings.TrimPrefix(account, p.Origin()+"/acme/acct/") + "/"
	return strings.HasPrefix(value, prefix) && positive(strings.TrimPrefix(value, prefix))
}

// No URL parsing, redirects, IDNA, normalization or caller-controlled base.
// Existing ACME authorization/challenge opaque segments retain their bounded
// ASCII grammar. Matching a URL is syntax, not proof it belongs to an order.
func (p Profile) ResourceURL(value, kind string) bool {
	if !p.Valid() || len(value) > 512 {
		return false
	}
	var prefixes []string
	switch kind {
	case "authorization":
		prefixes = []string{"/acme/authz/", "/acme/authz-v3/"}
	case "challenge":
		prefixes = []string{"/acme/chall/"}
	default:
		return false
	}
	for _, path := range prefixes {
		prefix := p.Origin() + path
		if !strings.HasPrefix(value, prefix) {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(value, prefix), "/")
		if len(parts) < 1 || len(parts) > 3 {
			return false
		}
		for _, part := range parts {
			if len(part) < 1 || len(part) > 128 {
				return false
			}
			for _, c := range part {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
					return false
				}
			}
		}
		return true
	}
	return false
}
