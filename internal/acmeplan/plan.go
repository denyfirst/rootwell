// Package acmeplan checks setup syntax only. It has no network, key creation,
// persistence, challenge token or issuance capability.
package acmeplan

import (
	"errors"
	"strings"

	"github.com/denyfirst/rootwell/internal/csrworkbench"
)

const Provider = "letsencrypt-staging"
const Directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
const Schema = "rootwell.acme.setup.v1"

var ErrInvalid = errors.New("ACME setup is invalid or unsupported")

type Plan struct {
	Schema         string   `json:"schema_version"`
	Provider       string   `json:"provider"`
	Directory      string   `json:"directory"`
	Challenge      string   `json:"challenge"`
	Domains        []string `json:"domains"`
	State          string   `json:"state"`
	NetworkEnabled bool     `json:"network_enabled"`
	Saved          bool     `json:"saved"`
	AccountCreated bool     `json:"account_created"`
	CanIssue       bool     `json:"can_issue"`
}

func Check(provider, challenge string, domains []string) (Plan, error) {
	if provider != Provider || (challenge != "dns-01" && challenge != "http-01") {
		return Plan{}, ErrInvalid
	}
	names, err := csrworkbench.NormalizeDNSNames(domains)
	if err != nil {
		return Plan{}, ErrInvalid
	}
	for _, name := range names {
		base := strings.TrimPrefix(name, "*.")
		if !strings.Contains(base, ".") || (name != base && challenge != "dns-01") {
			return Plan{}, ErrInvalid
		}
		for _, suffix := range []string{"local", "localhost", "internal", "invalid", "test", "example"} {
			if strings.HasSuffix(base, "."+suffix) {
				return Plan{}, ErrInvalid
			}
		}
	}
	return Plan{Schema: Schema, Provider: Provider, Directory: Directory, Challenge: challenge, Domains: names, State: "setup-checked"}, nil
}
