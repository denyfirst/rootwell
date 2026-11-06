package websitechain

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (chain []*x509.Certificate, roots *x509.CertPool, now time.Time) {
	t.Helper()
	now = time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	var parent *x509.Certificate
	var signer ed25519.PrivateKey
	for i, name := range []string{"Synthetic Root", "Synthetic Issuer", "website.example.org"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		c := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), BasicConstraintsValid: true}
		if i < 2 {
			c.IsCA = true
			c.KeyUsage = x509.KeyUsageCertSign
		} else {
			c.DNSNames = []string{name}
			c.KeyUsage = x509.KeyUsageDigitalSignature
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		if parent == nil {
			parent = c
			signer = key
		}
		der, err := x509.CreateCertificate(rand.Reader, c, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		chain = append([]*x509.Certificate{parsed}, chain...)
		parent, signer = parsed, key
	}
	roots = x509.NewCertPool()
	roots.AddCert(chain[2])
	return
}

func has(r Report, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestTrustedPathDoesNotNeedServerSentRoot(t *testing.T) {
	chain, roots, now := fixture(t)
	r, err := Analyze(chain[:2], roots, "website.example.org", now)
	if err != nil || r.State != "verified" || !r.Trusted || !r.HostnameMatches || len(r.Path) != 3 || r.Path[2].Sent || r.Path[2].Role != "trust-anchor" || r.Revocation != "not-checked" {
		t.Fatalf("valid path/root semantics: %+v %v", r, err)
	}
}

func TestSameIssuerNameCannotForgeSignatureLinkOrTrust(t *testing.T) {
	chain, roots, now := fixture(t)
	other, _, _ := fixture(t) // identical names, independent signing keys
	r, err := Analyze([]*x509.Certificate{chain[0], other[1]}, roots, "website.example.org", now)
	if err != nil || r.State != "failed" || r.Trusted || len(r.Path) != 1 || !has(r, "issuer-not-linked") {
		t.Fatalf("forged name became proof: %+v %v", r, err)
	}
}

func TestIssuerChecksLocateExactBrokenSignatureAtEachDepth(t *testing.T) {
	chain, roots, now := fixture(t)
	other, _, _ := fixture(t)
	good, err := Analyze(chain[:2], roots, "website.example.org", now)
	if err != nil || len(good.IssuerChecks) != 2 || len(good.IssuerChecks[0].Verified) != 1 || good.IssuerChecks[0].Verified[0] != good.Presented[1].Fingerprint || len(good.IssuerChecks[0].Rejected) != 0 {
		t.Fatal("valid child/issuer edge lost")
	}
	for _, input := range [][]*x509.Certificate{{chain[0], other[1]}, {chain[0], chain[1], other[2]}} {
		r, err := Analyze(input, x509.NewCertPool(), "website.example.org", now)
		depth := len(input) - 2
		if err != nil || len(r.IssuerChecks) != len(input) || r.IssuerChecks[depth].Child != r.Presented[depth].Fingerprint || len(r.IssuerChecks[depth].Rejected) != 1 || r.IssuerChecks[depth].Rejected[0] != r.Presented[depth+1].Fingerprint || len(r.IssuerChecks[depth].Verified) != 0 || r.Trusted {
			t.Fatalf("wrong edge localization at depth %d: %+v %v", depth, r, err)
		}
		if depth == 1 && (len(r.IssuerChecks[0].Verified) != 1 || !r.IssuerChecks[2].SelfSigned) {
			t.Fatal("good lower edge or self-signed root fact lost")
		}
	}
}

func TestMissingIssuerAndPeerRootCannotCreateTrust(t *testing.T) {
	chain, roots, now := fixture(t)
	for _, input := range [][]*x509.Certificate{chain[:1], chain} {
		pool := roots
		if len(input) == 3 {
			pool = x509.NewCertPool()
		}
		r, err := Analyze(input, pool, "website.example.org", now)
		if err != nil || r.State != "failed" || r.Trusted || !has(r, "trust") {
			t.Fatalf("missing issuer/unknown root trusted: %+v %v", r, err)
		}
		for _, c := range r.Path {
			if c.Role == "trust-anchor" {
				t.Fatal("peer root promoted")
			}
		}
		if len(input) == 3 && r.Path[2].Role != "root" {
			t.Fatal("unverified server root mislabeled")
		}
	}
}

func TestNameAndDatesAreSeparateFromPathLinks(t *testing.T) {
	chain, roots, now := fixture(t)
	r, err := Analyze(chain[:2], roots, "wrong.example.org", now)
	if err != nil || r.State != "failed" || !r.Trusted || r.HostnameMatches || !has(r, "hostname") {
		t.Fatal("wrong hostname accepted")
	}
	r, err = Analyze(chain[:2], roots, "website.example.org", now.Add(400*24*time.Hour))
	if err != nil || r.State != "failed" || r.Trusted || !has(r, "validity") || r.Path[0].InDate {
		t.Fatal("expired path accepted")
	}
}

func TestPresentationOrderDoesNotDeterminePath(t *testing.T) {
	chain, roots, now := fixture(t)
	r, err := Analyze([]*x509.Certificate{chain[0], chain[2], chain[1]}, roots, "website.example.org", now)
	if err != nil || !r.Trusted || r.State != "attention" || !has(r, "order") || r.Path[1].Fingerprint == r.Path[2].Fingerprint {
		t.Fatalf("order affected trust: %+v %v", r, err)
	}
}

func TestCrossSignedIssuerAmbiguityIsNotMissingOrWrongSignature(t *testing.T) {
	chain, roots, now := fixture(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(50), Subject: pkix.Name{CommonName: "Other synthetic root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issuer := *chain[1]
	issuer.SerialNumber = big.NewInt(51)
	crossDER, err := x509.CreateCertificate(rand.Reader, &issuer, root, chain[1].PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cross, err := x509.ParseCertificate(crossDER)
	if err != nil {
		t.Fatal(err)
	}
	if chain[0].CheckSignatureFrom(chain[1]) != nil || chain[0].CheckSignatureFrom(cross) != nil {
		t.Fatal("fixture does not have two real signing candidates")
	}
	r, err := Analyze([]*x509.Certificate{chain[0], chain[1], cross}, x509.NewCertPool(), "website.example.org", now)
	if err != nil || r.Trusted || r.State != "failed" || len(r.Path) != 1 || !has(r, "issuer-ambiguous") || has(r, "issuer-not-linked") {
		t.Fatalf("cross-sign ambiguity became false missing/wrong issuer: %+v %v", r, err)
	}
	r, err = Analyze([]*x509.Certificate{chain[0], chain[1], cross}, roots, "website.example.org", now)
	if err != nil || !r.Trusted || r.State != "attention" || len(r.Path) != 3 || has(r, "issuer-ambiguous") || has(r, "issuer-not-linked") {
		t.Fatal("a verifiable cross-signed alternative was falsely rejected")
	}
}

func TestMalformedAndBoundedInput(t *testing.T) {
	chain, roots, now := fixture(t)
	for _, input := range [][]*x509.Certificate{nil, {nil}, {chain[0], chain[0]}, make([]*x509.Certificate, MaxCertificates+1)} {
		if r, err := Analyze(input, roots, "website.example.org", now); err == nil || r.Schema != "" {
			t.Fatal("invalid input produced a report")
		}
	}
	if _, err := Analyze(chain, nil, "website.example.org", now); err == nil {
		t.Fatal("ambient roots allowed")
	}
	if got := safeText("\u202e\x1b<script>" + strings.Repeat("x", 200)); strings.ContainsAny(got, "\u202e\x1b") || len([]rune(got)) > 120 {
		t.Fatal("peer text unbounded")
	}
}

func FuzzAnalyzePublicChain(f *testing.F) {
	f.Add([]byte{0x30, 0})
	f.Add([]byte{})
	public, err := os.ReadFile("../../web/workbench/rootwell-verify-demo-leaf.pem")
	if err != nil {
		f.Fatal(err)
	}
	block, _ := pem.Decode(public)
	if block == nil {
		f.Fatal("missing public fixture")
	}
	f.Add(block.Bytes)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxCertificateBytes {
			return
		}
		c, err := x509.ParseCertificate(data)
		if err != nil {
			return
		}
		r, err := Analyze([]*x509.Certificate{c}, x509.NewCertPool(), "website.example.org", time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
		if err == nil && (r.Trusted || r.State != "failed") {
			t.Fatal("untrusted arbitrary certificate became trusted")
		}
	})
}
