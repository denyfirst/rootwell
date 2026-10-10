package acmeorder

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestManualDNSNamesURLsAndDigestAreBoundedCanonical(t *testing.T) {
	names, ok := Names([]string{"EXAMPLE.com", "*.example.com"})
	if !ok || !CanonicalNames(names) || names[0] != "*.example.com" {
		t.Fatal("normalization refused")
	}
	account := Origin + "/acme/acct/1234"
	url := Origin + "/acme/order/1234/5678"
	info := Instructions{URL: url, Expires: "2030-10-11T00:00:00Z", Records: []TXT{{names[0], "_acme-challenge.example.com", base64.RawURLEncoding.EncodeToString(make([]byte, 32)), true}, {names[1], "_acme-challenge.example.com", "", false}}}
	if !ValidInstructions(info, account, names) {
		t.Fatal("valid apex/wildcard instructions refused")
	}
	for _, bad := range []string{"", url + "?x=1", strings.Replace(url, "1234", "9999", 1), strings.Replace(url, "https:", "http:", 1), url + "/", Origin + "/acme/order/1234/01", url + "%00"} {
		if OrderURL(bad, account) {
			t.Fatal("unscoped URL accepted")
		}
	}
	for _, bad := range []string{strings.Repeat("A", 42) + "B", strings.Repeat("A", 42) + "=", "private sentinel"} {
		info.Records[0].Value = bad
		if ValidInstructions(info, account, names) {
			t.Fatal("noncanonical digest accepted")
		}
	}
	for _, bad := range [][]string{nil, {"example.com", "EXAMPLE.COM"}, {"127.0.0.1"}, {"localhost"}, {"a.test"}, {"*.example.com", "example.com", "a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com", "f.example.com", "g.example.com"}} {
		if _, ok := Names(bad); ok {
			t.Fatal("unbounded/invalid identifiers accepted")
		}
	}
	for _, bad := range []string{"2019-01-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-10-11T00:00:00+00:00", "2026-10-11T00:00:00.1Z"} {
		if Time(bad) {
			t.Fatal("noncanonical time accepted")
		}
	}
	for _, bad := range []string{Origin + "/acme/authz-v3/../1", Origin + "/acme/authz-v3/1?x=y", "https://evil.invalid/acme/authz-v3/1", Origin + "/acme/chall/1//2"} {
		if ResourceURL(bad, "authorization") || ResourceURL(bad, "challenge") {
			t.Fatal("unsafe reference accepted")
		}
	}
}
