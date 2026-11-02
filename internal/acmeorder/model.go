// Package acmeorder defines bounded manual-DNS order data, not network authority.
package acmeorder

import (
	"encoding/base64"
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/acmeprofile"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

const Origin = "https://acme-staging-v02.api.letsencrypt.org"

type TXT struct {
	Domain   string `json:"domain"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Required bool   `json:"required"`
}

type Instructions struct {
	URL     string             `json:"url"`
	Expires string             `json:"expires"`
	Records []TXT              `json:"records"`
	Wait    providerretry.Hint `json:"-"` // transient fixed-provider metadata, not a stored CA verdict
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
	return acmeprofile.Staging.AccountURL(value)
}

func OrderURL(value, account string) bool {
	return acmeprofile.Staging.OrderURL(value, account)
}

// Resource URLs come only from a validated order, never browser input. No
// credentials, queries, percent escapes, dot segments or other origins.
func ResourceURL(value, kind string) bool {
	return acmeprofile.Staging.ResourceURL(value, kind)
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
