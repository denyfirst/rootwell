package acmecertificate

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/acmecertrequest"
	"github.com/denyfirst/rootwell/internal/certverify"
	"github.com/denyfirst/rootwell/internal/keymatch"
)

type receiptFixture struct {
	private, csr            []byte
	key, rootKey, issuerKey *ecdsa.PrivateKey
	names                   []string
	at                      time.Time
	root, issuer            *x509.Certificate
	leafTemplate            x509.Certificate
	response                [][]byte
}

func fixture(t testing.TB, names []string) receiptFixture {
	t.Helper()
	private, csr, _, err := acmecertrequest.Create(names)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(private) })
	parsed, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("wrong fixture key type")
	}
	t.Cleanup(func() { keymatch.ClearParsedKey(key) })
	rootKey := generateKey(t)
	issuerKey := generateKey(t)
	at := time.Date(2026, 10, 12, 1, 2, 3, 0, time.UTC)
	rootTemplate := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "independent synthetic test root"},
		NotBefore: at.Add(-24 * time.Hour), NotAfter: at.Add(48 * time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 2}
	root := issue(t, &rootTemplate, &rootTemplate, rootKey.Public(), rootKey)
	issuerTemplate := rootTemplate
	issuerTemplate.SerialNumber = big.NewInt(2)
	issuerTemplate.Subject = pkix.Name{CommonName: "synthetic intermediate"}
	issuerTemplate.MaxPathLen = 0
	issuerTemplate.MaxPathLenZero = true
	issuer := issue(t, &issuerTemplate, root, issuerKey.Public(), rootKey)
	leafTemplate := x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: slices.Clone(names), NotBefore: at.Add(-time.Hour),
		NotAfter: at.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leaf := issue(t, &leafTemplate, issuer, key.Public(), issuerKey)
	return receiptFixture{private: private, csr: csr, key: key, rootKey: rootKey, issuerKey: issuerKey, names: names, at: at,
		root: root, issuer: issuer, leafTemplate: leafTemplate, response: [][]byte{leaf.Raw, issuer.Raw}}
}

func generateKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keymatch.ClearParsedKey(k) })
	return k
}

func issue(t testing.TB, template, parent *x509.Certificate, public any, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func assertRefused(t testing.TB, result Result, err error) {
	t.Helper()
	if err != ErrInvalid || !reflect.DeepEqual(result, Result{}) {
		t.Fatal("unsafe receipt or partial evidence accepted")
	}
}

func TestStagingReceiptExactBindingIndependentTrustAndNoInputMutation(t *testing.T) {
	for _, names := range [][]string{{"example.com"}, {"*.example.com"}, {"*.example.com", "example.com"}} {
		t.Run(strings.Join(names, "+"), func(t *testing.T) {
			f := fixture(t, names)
			beforeKey, beforeCSR := bytes.Clone(f.private), bytes.Clone(f.csr)
			defer clear(beforeKey)
			beforeChain := make([][]byte, len(f.response))
			for i, b := range f.response {
				beforeChain[i] = bytes.Clone(b)
			}
			roots := []*x509.Certificate{f.root}
			for _, chain := range [][][]byte{f.response, {f.response[0], f.response[1], f.root.Raw}} {
				out, err := check(f.private, f.csr, names, chain, f.at.In(time.FixedZone("operator", 4*3600)), roots)
				request, _ := acmecertrequest.Check(f.private, f.csr, names)
				if err != nil || !out.TestOnly || out.Fingerprint != fingerprint(f.response[0]) || out.PublicFingerprint != request.PublicFingerprint ||
					out.RequestFingerprint != request.RequestFingerprint || !slices.Equal(out.DNSNames, names) || !out.EvaluatedAt.Equal(f.at) || out.EvaluatedAt.Location() != time.UTC ||
					!slices.Equal(out.ChainFingerprints, []string{fingerprint(f.response[0]), fingerprint(f.issuer.Raw), fingerprint(f.root.Raw)}) ||
					!out.NotAfter.Equal(f.leafTemplate.NotAfter) || !out.NotBefore.Equal(f.leafTemplate.NotBefore) {
					t.Fatal("valid exact-name receipt refused or incorrectly summarized")
				}
				wire, err := json.Marshal(out)
				if err != nil || bytes.Contains(wire, []byte("PRIVATE")) || bytes.Contains(wire, []byte("private_key")) || bytes.Contains(wire, []byte("csr")) {
					t.Fatal("private/CSR output")
				}
				out.DNSNames[0] = "changed.example.com"
			}
			if !bytes.Equal(beforeKey, f.private) || !bytes.Equal(beforeCSR, f.csr) || !reflect.DeepEqual(beforeChain, f.response) || !slices.Equal(f.names, names) {
				t.Fatal("checker mutated caller input")
			}
			// Production entry cannot use the test seam's root, even supplied in response.
			out, err := Check(f.private, f.csr, names, [][]byte{f.response[0], f.response[1], f.root.Raw}, f.at)
			assertRefused(t, out, err)
		})
	}
}

func TestStagingReceiptRejectsAlteredNamesKeysUsageTimeAndSAN(t *testing.T) {
	f := fixture(t, []string{"*.example.com", "example.com"})
	other := generateKey(t)
	uri, _ := url.Parse("https://example.com/")
	ignoredSAN, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("*.example.com")},
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("example.com")}, {Class: asn1.ClassContextSpecific, Tag: 8, Bytes: []byte{42, 3, 4}}})
	if err != nil {
		t.Fatal(err)
	}
	unknownKU, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80, 0x08}, BitLength: 13})
	if err != nil {
		t.Fatal(err)
	}
	for label, mutate := range map[string]func(*x509.Certificate){
		"different-key":        func(c *x509.Certificate) {},
		"extra-name":           func(c *x509.Certificate) { c.DNSNames = append(slices.Clone(c.DNSNames), "evil.example.com") },
		"missing-name":         func(c *x509.Certificate) { c.DNSNames = []string{"example.com"} },
		"duplicate-name":       func(c *x509.Certificate) { c.DNSNames = append(slices.Clone(c.DNSNames), "example.com") },
		"uppercase-name":       func(c *x509.Certificate) { c.DNSNames = []string{"*.example.com", "EXAMPLE.COM"} },
		"ca-leaf":              func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign },
		"no-digital-signature": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
		"crl-sign":             func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCRLSign },
		"unknown-ku": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: unknownKU}}
		},
		"no-explicit-eku": func(c *x509.Certificate) { c.ExtKeyUsage = nil },
		"client-only":     func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
		"any-eku":         func(c *x509.Certificate) { c.ExtKeyUsage = append(slices.Clone(c.ExtKeyUsage), x509.ExtKeyUsageAny) },
		"other-eku": func(c *x509.Certificate) {
			c.ExtKeyUsage = append(slices.Clone(c.ExtKeyUsage), x509.ExtKeyUsageCodeSigning)
		},
		"duplicate-eku": func(c *x509.Certificate) {
			c.ExtKeyUsage = append(slices.Clone(c.ExtKeyUsage), x509.ExtKeyUsageServerAuth)
		},
		"unknown-eku":  func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}} },
		"expired":      func(c *x509.Certificate) { c.NotAfter = f.at },
		"future":       func(c *x509.Certificate) { c.NotBefore = f.at.Add(time.Second) },
		"empty-window": func(c *x509.Certificate) { c.NotAfter = c.NotBefore },
		"extra-ip":     func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} },
		"extra-email":  func(c *x509.Certificate) { c.EmailAddresses = []string{"test@example.com"} },
		"extra-uri":    func(c *x509.Certificate) { c.URIs = []*url.URL{uri} },
		"ignored-san-type": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: ignoredSAN}}
		},
		"unhandled-critical": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
		"unrequested-cn": func(c *x509.Certificate) { c.Subject.CommonName = "evil.example.com" },
	} {
		t.Run(label, func(t *testing.T) {
			c := f.leafTemplate
			mutate(&c)
			public := f.key.Public()
			if label == "different-key" {
				public = other.Public()
			}
			leaf := issue(t, &c, f.issuer, public, f.issuerKey)
			out, err := check(f.private, f.csr, f.names, [][]byte{leaf.Raw, f.issuer.Raw}, f.at, []*x509.Certificate{f.root})
			assertRefused(t, out, err)
		})
	}
	// Unsorted CA SANs and an explicitly requested CN/client usage remain valid.
	c := f.leafTemplate
	c.DNSNames = []string{"example.com", "*.example.com"}
	c.Subject.CommonName = "example.com"
	c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	leaf := issue(t, &c, f.issuer, f.key.Public(), f.issuerKey)
	if _, err := check(f.private, f.csr, f.names, [][]byte{leaf.Raw, f.issuer.Raw}, f.at, []*x509.Certificate{f.root}); err != nil {
		t.Fatal("allowed SAN order/CN/client usage refused")
	}
}

func TestStagingReceiptRejectsTamperUntrustedExtraneousChainAndResourceAbuse(t *testing.T) {
	f := fixture(t, []string{"example.com"})
	other := fixture(t, f.names)
	corrupt := bytes.Clone(f.response[0])
	corrupt[len(corrupt)-1] ^= 1
	badCSR := bytes.Clone(f.csr)
	badCSR[len(badCSR)-1] ^= 1
	many := make([][]byte, maxCertificates+1)
	for i := range many {
		many[i] = f.response[0]
	}
	for label, tc := range map[string]struct {
		key, csr []byte
		names    []string
		chain    [][]byte
		roots    []*x509.Certificate
		at       time.Time
	}{
		"bad-key":                {other.private, f.csr, f.names, f.response, []*x509.Certificate{f.root}, f.at},
		"bad-csr-signature":      {f.private, badCSR, f.names, f.response, []*x509.Certificate{f.root}, f.at},
		"bad-name-authority":     {f.private, f.csr, []string{"evil.example.com"}, f.response, []*x509.Certificate{f.root}, f.at},
		"tampered-leaf":          {f.private, f.csr, f.names, [][]byte{corrupt, f.issuer.Raw}, []*x509.Certificate{f.root}, f.at},
		"wrong-order":            {f.private, f.csr, f.names, [][]byte{f.issuer.Raw, f.response[0]}, []*x509.Certificate{f.root}, f.at},
		"duplicate":              {f.private, f.csr, f.names, [][]byte{f.response[0], f.issuer.Raw, f.issuer.Raw}, []*x509.Certificate{f.root}, f.at},
		"unrelated-extra":        {f.private, f.csr, f.names, [][]byte{f.response[0], f.issuer.Raw, other.issuer.Raw}, []*x509.Certificate{f.root}, f.at},
		"missing-intermediate":   {f.private, f.csr, f.names, [][]byte{f.response[0]}, []*x509.Certificate{f.root}, f.at},
		"supplied-root-no-trust": {f.private, f.csr, f.names, [][]byte{f.response[0], f.issuer.Raw, f.root.Raw}, nil, f.at},
		"wrong-independent-root": {f.private, f.csr, f.names, [][]byte{f.response[0], f.issuer.Raw, f.root.Raw}, []*x509.Certificate{other.root}, f.at},
		"not-root-anchor":        {f.private, f.csr, f.names, f.response, []*x509.Certificate{f.issuer}, f.at},
		"nil-anchor":             {f.private, f.csr, f.names, f.response, []*x509.Certificate{nil}, f.at},
		"der-trailing":           {f.private, f.csr, f.names, [][]byte{append(bytes.Clone(f.response[0]), 0), f.issuer.Raw}, []*x509.Certificate{f.root}, f.at},
		"pem-not-der":            {f.private, f.csr, f.names, [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.response[0]}), f.issuer.Raw}, []*x509.Certificate{f.root}, f.at},
		"empty-response":         {f.private, f.csr, f.names, nil, []*x509.Certificate{f.root}, f.at},
		"empty-member":           {f.private, f.csr, f.names, [][]byte{f.response[0], nil}, []*x509.Certificate{f.root}, f.at},
		"malformed-member":       {f.private, f.csr, f.names, [][]byte{f.response[0], {1, 2, 3}}, []*x509.Certificate{f.root}, f.at},
		"oversized-member":       {f.private, f.csr, f.names, [][]byte{bytes.Repeat([]byte{1}, maxCertificateBytes+1)}, []*x509.Certificate{f.root}, f.at},
		"too-many":               {f.private, f.csr, f.names, many, []*x509.Certificate{f.root}, f.at},
		"missing-time":           {f.private, f.csr, f.names, f.response, []*x509.Certificate{f.root}, time.Time{}},
		"root-expired":           {f.private, f.csr, f.names, f.response, []*x509.Certificate{f.root}, f.root.NotAfter},
	} {
		t.Run(label, func(t *testing.T) {
			out, err := check(tc.key, tc.csr, tc.names, tc.chain, tc.at, tc.roots)
			assertRefused(t, out, err)
		})
	}
}

func TestStagingReceiptEnforcesEveryIssuerPolicyAndNameConstraints(t *testing.T) {
	f := fixture(t, []string{"*.example.com", "example.com"})
	for label, mutate := range map[string]func(*x509.Certificate){
		"expired-intermediate": func(c *x509.Certificate) { c.NotAfter = f.at },
		"future-intermediate":  func(c *x509.Certificate) { c.NotBefore = f.at.Add(time.Second) },
		"issuer-not-ca":        func(c *x509.Certificate) { c.IsCA = false; c.MaxPathLen = -1; c.MaxPathLenZero = false },
		"issuer-no-signing":    func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
		"issuer-critical": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
		"issuer-disallows-server": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning} },
		"constraints-reject-names": func(c *x509.Certificate) {
			c.PermittedDNSDomainsCritical = true
			c.PermittedDNSDomains = []string{"unrelated.example.net"}
		},
		"constraints-exclude-names": func(c *x509.Certificate) { c.ExcludedDNSDomains = []string{"example.com"} },
	} {
		t.Run(label, func(t *testing.T) {
			c := *f.issuer
			mutate(&c)
			parent := issue(t, &c, f.root, f.issuerKey.Public(), f.rootKey)
			leaf := issue(t, &f.leafTemplate, parent, f.key.Public(), f.issuerKey)
			out, err := check(f.private, f.csr, f.names, [][]byte{leaf.Raw, parent.Raw}, f.at, []*x509.Certificate{f.root})
			assertRefused(t, out, err)
		})
	}
	weakKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer keymatch.ClearParsedKey(weakKey)
	weak := issue(t, f.issuer, f.root, weakKey.Public(), f.rootKey)
	leaf := issue(t, &f.leafTemplate, weak, f.key.Public(), weakKey)
	out, err := check(f.private, f.csr, f.names, [][]byte{leaf.Raw, weak.Raw}, f.at, []*x509.Certificate{f.root})
	assertRefused(t, out, err)
	c := *f.issuer
	c.PermittedDNSDomainsCritical = true
	c.PermittedDNSDomains = []string{"example.com"}
	parent := issue(t, &c, f.root, f.issuerKey.Public(), f.rootKey)
	leaf = issue(t, &f.leafTemplate, parent, f.key.Public(), f.issuerKey)
	if _, err := check(f.private, f.csr, f.names, [][]byte{leaf.Raw, parent.Raw}, f.at, []*x509.Certificate{f.root}); err != nil {
		t.Fatal("permitted apex/wildcard constraint refused")
	}
}

func TestStagingRootsExactOfficialAssetsAndNoFallback(t *testing.T) {
	roots, err := stagingTrust()
	names := []string{"(STAGING) Pretend Pear X1", "(STAGING) Bogus Broccoli X2", "(STAGING) Yearning Yucca Root YE", "(STAGING) Yonder Yam Root YR"}
	hashes := []string{"E70570A989F8565AABDF7CAE27ABD1621872D6A3F811E3FEF27E3DBA02912198", "9B2A339FE6A3E85585C4CD75536CB8C1CF7CD603B9A64BEC2521858AE48DA85D",
		"B59BFC0BA52DAF849853B7324A91E82F031DB3397F35644157352CDE6384B56C", "EF115FB59E040FF39D15FD8F3EF54063C704321D83CB081213272F77D3091672"}
	if err != nil || len(roots) != 4 {
		t.Fatal("reviewed staging roots unavailable")
	}
	for i, r := range roots {
		digest := sha256.Sum256(r.Raw)
		if r.Subject.CommonName != names[i] || strings.ToUpper(hex.EncodeToString(digest[:])) != hashes[i] || r.CheckSignatureFrom(r) != nil || certverify.CheckCertificatePolicy(r) != nil {
			t.Fatal("root source/policy/self-signature drift")
		}
	}
	// Mutating a returned parsed object cannot alter subsequent independent trust.
	roots[0].Raw[0] ^= 1
	if _, err := stagingTrust(); err != nil {
		t.Fatal("trust result aliases global bytes")
	}
	var blocks [][]byte
	remaining := []byte(stagingRootPEM)
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			t.Fatal("fixture asset malformed")
		}
		blocks = append(blocks, pem.EncodeToMemory(block))
		remaining = rest
	}
	fake := fixture(t, []string{"example.com"})
	wrongRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fake.root.Raw})
	for _, bad := range []string{"", "bad", strings.Repeat(" ", maxRootBytes+1), string(bytes.Join(blocks[1:], nil)),
		string(bytes.Join([][]byte{blocks[1], blocks[0], blocks[2], blocks[3]}, nil)),
		string(bytes.Join([][]byte{wrongRoot, blocks[1], blocks[2], blocks[3]}, nil)), stagingRootPEM + string(blocks[0])} {
		if out, err := checkedStagingRoots(bad); err != ErrInvalid || out != nil {
			t.Fatal("changed/missing roots granted trust")
		}
	}
}

func TestStagingReceiptDirectRootCrossSignedPathAndResponseBudget(t *testing.T) {
	f := fixture(t, []string{"example.com"})
	direct := issue(t, &f.leafTemplate, f.root, f.key.Public(), f.rootKey)
	for _, chain := range [][][]byte{{direct.Raw}, {direct.Raw, f.root.Raw}} {
		if out, err := check(f.private, f.csr, f.names, chain, f.at, []*x509.Certificate{f.root}); err != nil || len(out.ChainFingerprints) != 2 {
			t.Fatal("direct root path refused")
		}
	}
	second := fixture(t, f.names)
	cross := issue(t, f.root, second.root, f.rootKey.Public(), second.rootKey)
	chain := [][]byte{f.response[0], f.issuer.Raw, cross.Raw}
	if out, err := check(f.private, f.csr, f.names, chain, f.at, []*x509.Certificate{second.root}); err != nil || len(out.ChainFingerprints) != 4 {
		t.Fatal("cross-signed path refused")
	}
	// All supplied members must be used; x509 may shorten a chain when both
	// roots are trusted. A shorter alternative is not evidence for the bundle.
	out, err := check(f.private, f.csr, f.names, chain, f.at, []*x509.Certificate{f.root})
	assertRefused(t, out, err)
	// An unused older anchor can expire without invalidating an independent
	// current path; the selected anchor's time is always enforced.
	expiredTemplate := *second.root
	expiredTemplate.NotAfter = f.at
	expiredOther := issue(t, &expiredTemplate, &expiredTemplate, second.rootKey.Public(), second.rootKey)
	if _, err := check(f.private, f.csr, f.names, f.response, f.at, []*x509.Certificate{expiredOther, f.root}); err != nil {
		t.Fatal("unused expired anchor invalidated a current path")
	}
	expiredTemplate = *f.root
	expiredTemplate.NotAfter = f.at
	expiredSelected := issue(t, &expiredTemplate, &expiredTemplate, f.rootKey.Public(), f.rootKey)
	out, err = check(f.private, f.csr, f.names, f.response, f.at, []*x509.Certificate{expiredSelected})
	assertRefused(t, out, err)

	// Same valid eight-member path, first small, then 40 KiB noncritical public
	// extensions on every non-root member. Only the aggregate budget changes.
	rootTemplate := *f.root
	rootTemplate.MaxPathLen = 6
	root := issue(t, &rootTemplate, &rootTemplate, f.rootKey.Public(), f.rootKey)
	keys := make([]*ecdsa.PrivateKey, 6)
	for i := range keys {
		keys[i] = generateKey(t)
	}
	payload, err := asn1.Marshal(bytes.Repeat([]byte{1}, 40<<10))
	if err != nil {
		t.Fatal(err)
	}
	for _, large := range []bool{false, true} {
		parent, parentKey := root, f.rootKey
		path := [][]byte{root.Raw}
		for i, k := range keys {
			c := *f.issuer
			c.SerialNumber = big.NewInt(int64(10 + i))
			c.Subject.CommonName = "bounded issuer " + string(rune('A'+i))
			c.MaxPathLen = 5 - i
			c.MaxPathLenZero = i == 5
			if large {
				c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: payload}}
			}
			parent = issue(t, &c, parent, k.Public(), parentKey)
			parentKey = k
			path = append([][]byte{parent.Raw}, path...)
		}
		leafTemplate := f.leafTemplate
		if large {
			leafTemplate.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: payload}}
		}
		leaf := issue(t, &leafTemplate, parent, f.key.Public(), parentKey)
		path = append([][]byte{leaf.Raw}, path...)
		total := 0
		for _, der := range path {
			if len(der) > maxCertificateBytes {
				t.Fatal("fixture exceeds individual limit")
			}
			total += len(der)
		}
		out, err := check(f.private, f.csr, f.names, path, f.at, []*x509.Certificate{root})
		if large {
			if total <= maxResponseBytes {
				t.Fatal("fixture does not exceed aggregate budget")
			}
			assertRefused(t, out, err)
		} else if err != nil || len(out.ChainFingerprints) != 8 {
			t.Fatal("valid bounded longest path refused")
		}
	}
}

func TestStagingReceiptCapsRSAIssuerWorkBeforeSignatureVerification(t *testing.T) {
	f := fixture(t, []string{"example.com"})
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	defer keymatch.ClearParsedKey(key)
	parent := issue(t, f.issuer, f.root, key.Public(), f.rootKey)
	leaf := issue(t, &f.leafTemplate, parent, f.key.Public(), key)
	if _, err := check(f.private, f.csr, f.names, [][]byte{leaf.Raw, parent.Raw}, f.at, []*x509.Certificate{f.root}); err != nil {
		t.Fatal("normal RSA issuer refused")
	}
	// Public-only fabricated moduli are cheap fixtures, not huge key generation.
	// These valid signed certificates are small and meet the inherited key floor;
	// ONLY the new receipt work-factor ceiling refuses the oversized public key.
	for _, bits := range []int{2048, 4096, 8192, 8193, 65536} {
		modulus := new(big.Int).SetBit(new(big.Int), bits-1, 1)
		modulus.SetBit(modulus, 0, 1)
		c := issue(t, f.issuer, f.root, &rsa.PublicKey{N: modulus, E: 65537}, f.rootKey)
		if len(c.Raw) > maxCertificateBytes || certverify.CheckCertificatePolicy(c) != nil || c.CheckSignatureFrom(f.root) != nil {
			t.Fatal("fixture does not isolate RSA ceiling")
		}
		if validMember(c, f.at) != (bits <= 8192) {
			t.Fatal("RSA work ceiling failed before path verification")
		}
	}
}

func FuzzStagingCertificateReceipt(f *testing.F) {
	test := fixture(f, []string{"example.com"})
	f.Add(test.response[0], test.csr, test.private)
	f.Add([]byte("bad"), test.csr, test.private)
	f.Add(test.response[0], []byte("bad"), test.private)
	f.Fuzz(func(t *testing.T, leaf, csr, private []byte) {
		if len(leaf) > maxCertificateBytes+1 || len(csr) > 4097 || len(private) > 513 {
			return
		}
		out, err := check(private, csr, test.names, [][]byte{leaf, test.issuer.Raw}, test.at, []*x509.Certificate{test.root})
		if err != nil {
			assertRefused(t, out, err)
			return
		}
		if !out.TestOnly || out.PublicFingerprint == "" || out.Fingerprint != fingerprint(leaf) || !slices.Equal(out.DNSNames, test.names) || len(out.ChainFingerprints) != 3 {
			t.Fatal("unbound success evidence")
		}
	})
}
