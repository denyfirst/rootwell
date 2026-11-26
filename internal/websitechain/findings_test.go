package websitechain

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

type issued struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

var serial int64 = 1000

// issue signs a certificate for name with parent, or self-signs it when
// parent is nil. A CA gets certificate-signing use; anything else is a
// website certificate for name.
func issue(t testing.TB, name string, ca bool, parent *issued, from, to time.Time) issued {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return sign(t, name, ca, pub, key, parent, from, to)
}

// sign certifies pub under name: with parent's key, or self-signed with key.
func sign(t testing.TB, name string, ca bool, pub ed25519.PublicKey, key ed25519.PrivateKey, parent *issued, from, to time.Time) issued {
	t.Helper()
	serial++
	c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: from, NotAfter: to, BasicConstraintsValid: true}
	if ca {
		c.IsCA = true
		c.KeyUsage = x509.KeyUsageCertSign
	} else {
		c.DNSNames = []string{name}
		c.KeyUsage = x509.KeyUsageDigitalSignature
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signer, signerCert := key, c
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, c, signerCert, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return issued{parsed, key}
}

func finding(r Report, code string) Finding {
	for _, f := range r.Findings {
		if f.Code == code {
			return f
		}
	}
	return Finding{}
}

func fingerprintOf(c *x509.Certificate) string { return describe(c, "", 0, time.Now()).Fingerprint }

// What emanat.az sends: the chain to a newer root, then that root's copy
// signed by an older root, the older root's copy signed by the oldest, and the
// oldest root itself. Only a root is worth a note; nothing needs fixing.
func TestOlderChainAndSentRootAreNotProblems(t *testing.T) {
	now := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	from, to := now.Add(-time.Hour), now.Add(365*24*time.Hour)
	oldest := issue(t, "AAA Certificate Services", true, nil, from, to)
	older := issue(t, "USERTrust RSA Certification Authority", true, nil, from, to)
	newer := issue(t, "Sectigo Public Server Authentication Root R46", true, nil, from, to)
	olderCross := sign(t, older.cert.Subject.CommonName, true, older.cert.PublicKey.(ed25519.PublicKey), older.key, &oldest, from, to)
	newerCross := sign(t, newer.cert.Subject.CommonName, true, newer.cert.PublicKey.(ed25519.PublicKey), newer.key, &older, from, to)
	intermediate := issue(t, "Sectigo Public Server Authentication CA DV R36", true, &newer, from, to)
	leaf := issue(t, "website.example.org", false, &intermediate, from, to)
	roots := x509.NewCertPool()
	roots.AddCert(newer.cert)
	sent := []*x509.Certificate{leaf.cert, intermediate.cert, newerCross.cert, olderCross.cert, oldest.cert}
	r, err := Analyze(sent, roots, "website.example.org", now)
	if err != nil || !r.Trusted || r.State != "verified" || r.TrustSource != "public" || len(r.Path) != 3 {
		t.Fatalf("a valid chain with an older chain was not in order: %s %+v %v", r.State, r.Findings, err)
	}
	wantUse := []string{"path", "path", "older-path", "older-path", "root"}
	for i, c := range r.Presented {
		if c.Use != wantUse[i] {
			t.Fatalf("sent certificate %d (%s) is %q, want %q", i+1, c.Subject, c.Use, wantUse[i])
		}
	}
	olderNote, rootNote := finding(r, "older-chain"), finding(r, "sent-root")
	if olderNote.Level != "note" || len(olderNote.Certificates) != 2 || rootNote.Level != "note" ||
		!slices.Equal(rootNote.Certificates, []string{fingerprintOf(oldest.cert)}) || !strings.Contains(rootNote.Detail, "AAA Certificate Services") {
		t.Fatalf("older chain or sent root not explained: %+v", r.Findings)
	}
	if has(r, "unrelated") || has(r, "extra-expired") {
		t.Fatalf("a needed certificate was called a mistake: %+v", r.Findings)
	}
	// Without the newer root, the same certificates fail and say so; the
	// server-sent oldest root never becomes trusted.
	r, err = Analyze(sent, x509.NewCertPool(), "website.example.org", now)
	if err != nil || r.Trusted || r.State != "failed" || r.TrustSource != "" {
		t.Fatalf("a sent root became trusted: %+v %v", r, err)
	}
	// An expired copy in the older chain is worth fixing, but the site works.
	expiredCross := sign(t, older.cert.Subject.CommonName, true, older.cert.PublicKey.(ed25519.PublicKey), older.key, &oldest, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	r, err = Analyze([]*x509.Certificate{leaf.cert, intermediate.cert, newerCross.cert, expiredCross.cert}, roots, "website.example.org", now)
	if err != nil || !r.Trusted || r.State != "attention" || !slices.Equal(finding(r, "extra-expired").Certificates, []string{fingerprintOf(expiredCross.cert)}) {
		t.Fatalf("an expired extra certificate was not named: %s %+v %v", r.State, r.Findings, err)
	}
}

func TestMissingIntermediateNamesTheIssuer(t *testing.T) {
	chain, roots, now := fixture(t)
	r, err := Analyze(chain[:1], roots, "website.example.org", now)
	f := finding(r, "missing-issuer")
	if err != nil || r.State != "failed" || f.Level != "failed" || !strings.Contains(f.Title, "Synthetic Issuer") ||
		!strings.Contains(f.Action, "fullchain") || len(f.Certificates) != 0 {
		t.Fatalf("missing intermediate not named: %+v %v", r.Findings, err)
	}
}

func TestSelfSignedWebsiteCertificateIsNamed(t *testing.T) {
	now := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	self := issue(t, "website.example.org", false, nil, now.Add(-time.Hour), now.Add(time.Hour))
	r, err := Analyze([]*x509.Certificate{self.cert}, x509.NewCertPool(), "website.example.org", now)
	if err != nil || r.State != "failed" || !has(r, "self-signed") || has(r, "missing-issuer") {
		t.Fatalf("self-signed certificate not explained: %+v %v", r.Findings, err)
	}
}

func TestSavedRootTrustsAPrivateChainAndNothingElse(t *testing.T) {
	chain, _, now := fixture(t)
	empty := x509.NewCertPool()
	// The server sends its private root: complete, but nobody public trusts it.
	r, err := Analyze(chain, empty, "website.example.org", now)
	f := finding(r, "untrusted-root")
	if err != nil || r.Trusted || f.Level != "failed" || !strings.Contains(f.Title, "Synthetic Root") || !slices.Equal(f.Certificates, []string{fingerprintOf(chain[2])}) {
		t.Fatalf("a private root was not named: %+v %v", r.Findings, err)
	}
	// The sent private root is the end of the chain, shown once; devices do
	// not have it, so it is not "a root devices already have".
	if has(r, "sent-root") || r.Presented[2].Use != "path" {
		t.Fatalf("a private root was called a root devices have: %+v %+v", r.Findings, r.Presented)
	}
	// A public root the server sends is on the chain and noted once.
	_, publicRoots, _ := fixture(t)
	publicRoots.AddCert(chain[2])
	r, err = Analyze(chain, publicRoots, "website.example.org", now)
	if err != nil || !r.Trusted || r.Presented[2].Use != "path" || finding(r, "sent-root").Level != "note" || r.State != "verified" {
		t.Fatalf("a sent public root was not noted once: %+v %v", r, err)
	}
	// The person saved that root in Certificates: trusted, and said so.
	for _, sent := range [][]*x509.Certificate{chain, chain[:2]} {
		r, err = AnalyzeWithSaved(sent, empty, []*x509.Certificate{chain[2]}, "website.example.org", now)
		if err != nil || !r.Trusted || r.State != "verified" || r.TrustSource != "saved" || r.SavedRoot != "Synthetic Root" || finding(r, "saved-root").Level != "note" {
			t.Fatalf("a saved root did not trust its own chain: %s %+v %v", r.State, r.Findings, err)
		}
	}
	// A saved root says nothing about another company's chain.
	other, _, _ := fixture(t)
	r, err = AnalyzeWithSaved(chain[:2], empty, []*x509.Certificate{other[2]}, "website.example.org", now)
	if err != nil || r.Trusted || r.TrustSource != "" {
		t.Fatalf("an unrelated saved root created trust: %+v %v", r, err)
	}
	// Only a self-signed certificate authority can be a saved root.
	for _, bad := range [][]*x509.Certificate{{chain[1]}, {chain[0]}, {nil}, slices.Repeat([]*x509.Certificate{chain[2]}, MaxSavedRoots+1)} {
		if r, err := AnalyzeWithSaved(chain[:2], empty, bad, "website.example.org", now); err == nil || r.Schema != "" {
			t.Fatal("a certificate that is not a root was used as a saved root")
		}
	}
}

func TestExpiredIntermediateIsNamed(t *testing.T) {
	now := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	root := issue(t, "Synthetic Root", true, nil, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	issuer := issue(t, "Synthetic Issuer", true, &root, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	leaf := issue(t, "website.example.org", false, &issuer, now.Add(-time.Hour), now.Add(24*time.Hour))
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	r, err := Analyze([]*x509.Certificate{leaf.cert, issuer.cert}, roots, "website.example.org", now)
	f := finding(r, "validity")
	if err != nil || r.State != "failed" || !strings.Contains(f.Title, "Synthetic Issuer") || !strings.Contains(f.Title, "expired") || !slices.Equal(f.Certificates, []string{fingerprintOf(issuer.cert)}) {
		t.Fatalf("expired intermediate not named: %+v %v", r.Findings, err)
	}
	// The leaf ends within a day: named with its date once the chain is current.
	issuer = issue(t, "Synthetic Issuer", true, &root, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	leaf = issue(t, "website.example.org", false, &issuer, now.Add(-time.Hour), now.Add(12*time.Hour))
	r, err = Analyze([]*x509.Certificate{leaf.cert, issuer.cert}, roots, "website.example.org", now)
	if f := finding(r, "expires-soon"); err != nil || r.State != "attention" || !strings.Contains(f.Title, "website.example.org") || !slices.Equal(f.Certificates, []string{fingerprintOf(leaf.cert)}) {
		t.Fatalf("expiry not named: %+v %v", r.Findings, err)
	}
}

func TestWrongNameListsWhatTheCertificateCovers(t *testing.T) {
	chain, roots, now := fixture(t)
	r, err := Analyze(chain[:2], roots, "10.0.0.5", now)
	f := finding(r, "hostname")
	if err != nil || r.HostnameMatches || !strings.Contains(f.Title, "10.0.0.5") || !strings.Contains(f.Detail, "website.example.org") {
		t.Fatalf("name finding unclear: %+v %v", r.Findings, err)
	}
}
