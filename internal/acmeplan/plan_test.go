package acmeplan

import (
	"reflect"
	"strings"
	"testing"
)

func TestACMEPlanChecksSyntaxWithoutGrantingCapabilities(t *testing.T) {
	for _, challenge := range []string{"dns-01", "http-01"} {
		p, err := Check(Provider, challenge, []string{" EXAMPLE.com ", "www.example.com"})
		if err != nil || p.Schema != Schema || p.Directory != Directory || p.State != "setup-checked" || p.Provider != Provider || p.Challenge != challenge || !reflect.DeepEqual(p.Domains, []string{"example.com", "www.example.com"}) || p.NetworkEnabled || p.Saved || p.AccountCreated || p.CanIssue {
			t.Fatal("valid syntax refused or execution capability granted")
		}
	}
	if p, err := Check(Provider, "dns-01", []string{"*.example.com", "example.com"}); err != nil || len(p.Domains) != 2 {
		t.Fatal("valid wildcard/apex plan refused")
	}
	for _, names := range [][]string{nil, {}, {"example.com", "EXAMPLE.com"}, {""}, {"localhost"}, {"foo.local"}, {"foo.invalid"}, {"foo.test"}, {"foo.internal"}, {"https://example.com"}, {"127.0.0.1"}, {"[::1]"}, {"example.com:443"}, {"a..com"}, {"-a.com"}, {"a_.com"}, {"x\x00.com"}, {"bücher.com"}, {"a.com."}, {strings.Repeat("x", 64) + ".com"}, make([]string, 33)} {
		if p, err := Check(Provider, "dns-01", names); err == nil || len(p.Domains) != 0 || p.Directory != "" {
			t.Fatal("invalid input returned full or partial plan")
		}
	}
	for _, p := range []string{"letsencrypt-production", "https://evil.invalid", "https://127.0.0.1/", ""} {
		if _, err := Check(p, "dns-01", []string{"example.com"}); err == nil {
			t.Fatal("custom/production provider allowed")
		}
	}
	for _, c := range []string{"tls-alpn-01", "", "shell"} {
		if _, err := Check(Provider, c, []string{"example.com"}); err == nil {
			t.Fatal("unknown proof allowed")
		}
	}
	if _, err := Check(Provider, "http-01", []string{"*.example.com"}); err == nil {
		t.Fatal("HTTP wildcard accepted")
	}
	for _, name := range []string{"\u212a.example.com", "\u00a0example.com", "example.com\u00a0"} {
		if _, err := Check(Provider, "dns-01", []string{name}); err == nil {
			t.Fatal("Unicode accepted before case folding/trimming")
		}
	}
}
