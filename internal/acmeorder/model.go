// Package acmeorder defines bounded manual-DNS order data, not network authority.
package acmeorder

import (
	"encoding/base64"
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeplan"
)

const Origin = "https://acme-staging-v02.api.letsencrypt.org"

type TXT struct {
	Domain   string `json:"domain"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Required bool   `json:"required"`
}

type Instructions struct {
	URL     string `json:"url"`
	Expires string `json:"expires"`
	Records []TXT  `json:"records"`
}

func Names(input []string) ([]string, bool) {
	p, err := acmeplan.Check(acmeplan.Provider, "dns-01", input)
	if err != nil || len(p.Domains) > 8 {
		return nil, false
	}
	slices.Sort(p.Domains)
	return p.Domains, true
}

func CanonicalNames(names []string) bool {
	normal, ok := Names(names)
	return ok && slices.Equal(normal, names)
}

func AccountURL(value string) bool {
	const prefix = Origin + "/acme/acct/"
	return strings.HasPrefix(value, prefix) && positive(strings.TrimPrefix(value, prefix))
}

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

func OrderURL(value, account string) bool {
	if !AccountURL(account) {
		return false
	}
	prefix := Origin + "/acme/order/" + strings.TrimPrefix(account, Origin+"/acme/acct/") + "/"
	return strings.HasPrefix(value, prefix) && positive(strings.TrimPrefix(value, prefix))
}

// Resource URLs come only from a validated order, never browser input. No
// credentials, queries, percent escapes, dot segments or other origins.
func ResourceURL(value, kind string) bool {
	prefixes := []string{}
	switch kind {
	case "authorization":
		prefixes = []string{"/acme/authz/", "/acme/authz-v3/"}
	case "challenge":
		prefixes = []string{"/acme/chall/"}
	}
	for _, path := range prefixes {
		prefix := Origin + path
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

func Time(value string) bool {
	at, err := time.Parse(time.RFC3339, value)
	return err == nil && at.Year() >= 2020 && at.Year() <= 9999 && at.UTC().Format("2006-01-02T15:04:05Z") == value
}

func ValidInstructions(info Instructions, account string, names []string) bool {
	if !OrderURL(info.URL, account) || !Time(info.Expires) || !CanonicalNames(names) || len(info.Records) != len(names) {
		return false
	}
	for i, record := range info.Records {
		if record.Domain != names[i] || record.Name != "_acme-challenge."+strings.TrimPrefix(names[i], "*.") {
			return false
		}
		if !record.Required {
			if record.Value != "" {
				return false
			}
			continue
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(record.Value)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != record.Value {
			return false
		}
	}
	return true
}
