package acmeprofile

import (
	"errors"
	"strings"
	"testing"
)

func TestFixedACMEProfilesSeparateOriginsAccountsAndNamespaces(t *testing.T) {
	for _, p := range []Profile{Staging, Production} {
		parsed, err := Parse(p.Provider())
		if err != nil || parsed != p || !p.Valid() || p.Host() == "" || p.Directory() != p.Origin()+"/directory" || p.Namespace() == "" || p.TestOnly() != (p == Staging) {
			t.Fatal("valid immutable profile refused", p, err)
		}
		account := p.Origin() + "/acme/acct/1234"
		order := p.Origin() + "/acme/order/1234/5678"
		if !p.AccountURL(account) || !p.OrderURL(order, account) || p.OrderURL(order, p.Origin()+"/acme/acct/9999") {
			t.Fatal("account/order identity lost", p)
		}
		for _, kind := range []string{"authorization", "challenge"} {
			path := "/acme/authz/"
			if kind == "challenge" {
				path = "/acme/chall/"
			}
			if !p.ResourceURL(p.Origin()+path+"1234/ABC_def-12", kind) {
				t.Fatal("bounded resource refused", p, kind)
			}
		}
		other := Staging
		if p == Staging {
			other = Production
		}
		if p.Namespace() == other.Namespace() || p.AccountURL(other.Origin()+"/acme/acct/1234") || p.OrderURL(other.Origin()+"/acme/order/1234/5678", account) || p.OrderURL(order, other.Origin()+"/acme/acct/1234") || p.ResourceURL(other.Origin()+"/acme/authz/1234", "authorization") {
			t.Fatal("environments mixed", p)
		}
	}
}

func TestFixedACMEProfilesUnknownAndMalformedNeverSelectDefault(t *testing.T) {
	for _, id := range []string{"", "production", "letsencrypt", " letsencrypt-production", "letsencrypt-production ", "LETSENCRYPT-PRODUCTION", "https://acme-v02.api.letsencrypt.org/directory", "letsencrypt-production\x00", "letsencrypt-ｐroduction"} {
		if p, err := Parse(id); !errors.Is(err, ErrInvalid) || p != 0 {
			t.Fatal("unknown identity selected profile", id)
		}
	}
	for _, p := range []Profile{0, 3, 255} {
		if p.Valid() || p.Provider() != "" || p.Host() != "" || p.Origin() != "" || p.Directory() != "" || p.Namespace() != "" || p.TestOnly() || p.AccountURL(Staging.Origin()+"/acme/acct/1") || p.OrderURL(Staging.Origin()+"/acme/order/1/2", Staging.Origin()+"/acme/acct/1") || p.ResourceURL(Staging.Origin()+"/acme/authz/1", "authorization") {
			t.Fatal("invalid profile acquired defaults", p)
		}
	}
	for _, p := range []Profile{Staging, Production} {
		origin := p.Origin()
		account := origin + "/acme/acct/1234"
		order := origin + "/acme/order/1234/5678"
		auth := origin + "/acme/authz/1234"
		for _, bad := range []string{account + "/", account + "?x=1", account + "#x", account + "%00", origin + "/acme/acct/01234", origin + "/acme/acct/" + strings.Repeat("1", 65), strings.Replace(account, "https://", "http://", 1), strings.Replace(account, "https://", "https://user@", 1), strings.Replace(account, "/acme/", ":443/acme/", 1), strings.Replace(account, p.Host(), strings.ToUpper(p.Host()), 1)} {
			if p.AccountURL(bad) {
				t.Fatal("bad account accepted", bad)
			}
		}
		for _, bad := range []string{order + "/", order + "?a=1", order + "#fragment", order + "%2f", strings.Replace(order, "/1234/", "/9999/", 1), strings.Replace(order, "/5678", "/05678", 1)} {
			if p.OrderURL(bad, account) {
				t.Fatal("bad order accepted", bad)
			}
		}
		for _, bad := range []string{auth + "/", auth + "?a=1", auth + "#x", auth + "%2f", auth + "/../456", auth + "/a/b/c", origin + "/acme/authz/" + strings.Repeat("a", 129), auth + "\r\nHost: evil", strings.Replace(auth, "/acme/", "//acme/", 1)} {
			if p.ResourceURL(bad, "authorization") {
				t.Fatal("bad resource accepted", bad)
			}
		}
		if p.ResourceURL(auth, "directory") || p.ResourceURL(auth, "challenge") || p.ResourceURL(origin+"/acme/chall/1", "authorization") {
			t.Fatal("resource kind crossed")
		}
	}
}

func FuzzFixedACMEProfileURLs(f *testing.F) {
	f.Add("letsencrypt-production", "https://acme-v02.api.letsencrypt.org/acme/acct/1", "https://acme-v02.api.letsencrypt.org/acme/order/1/2", "authorization")
	f.Add("letsencrypt-staging", "", "", "challenge")
	f.Fuzz(func(t *testing.T, name, account, value, kind string) {
		if len(name)+len(account)+len(value)+len(kind) > 8192 {
			t.Skip()
		}
		p, err := Parse(name)
		if err != nil {
			if p != 0 {
				t.Fatal("partial profile")
			}
			return
		}
		other := Staging
		if p == Staging {
			other = Production
		}
		if p.AccountURL(account) && other.AccountURL(account) || p.OrderURL(value, account) && other.OrderURL(value, account) || p.ResourceURL(value, kind) && other.ResourceURL(value, kind) {
			t.Fatal("accepted in two environments")
		}
		if (p.AccountURL(value) || p.OrderURL(value, account) || p.ResourceURL(value, kind)) && !strings.HasPrefix(value, p.Origin()+"/acme/") {
			t.Fatal("foreign origin accepted")
		}
	})
}
