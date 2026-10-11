// Package acmecertificate checks an issued response against the exact prepared
// key/CSR and independent test-only staging roots. It performs no I/O, issuance,
// revocation or storage and never consults system trust.
package acmecertificate

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/acmecertrequest"
	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/certverify"
)

var ErrInvalid = errors.New("staging certificate response could not be safely accepted")

const (
	maxCertificates     = 8
	maxCertificateBytes = 48 << 10
	maxResponseBytes    = 256 << 10
	maxRootBytes        = 32 << 10
)

// Result is public evidence only, not CA order, revocation or deployment
// authority. A caller must repeat Check before an atomic pair commit.
type Result struct {
	TestOnly                         bool
	Fingerprint                      string
	PublicFingerprint                string
	RequestFingerprint               string
	DNSNames                         []string
	NotBefore, NotAfter, EvaluatedAt time.Time
	ChainFingerprints                []string // leaf through independent root; no key or DER
}

// Check selects only the reviewed embedded staging roots. Response-supplied
// roots, host trust, arbitrary trust configuration and network are not options.
// The caller owns private and clears it after custody use; no input is mutated.
func Check(private, csr []byte, names []string, response [][]byte, at time.Time) (Result, error) {
	roots, err := stagingTrust()
	if err != nil {
		return Result{}, ErrInvalid
	}
	return check(private, csr, names, response, at, roots)
}

// Independent roots are a test seam only; no route or exported API accepts them.
func check(private, csr []byte, names []string, response [][]byte, at time.Time, roots []*x509.Certificate) (Result, error) {
	bad := func() (Result, error) { return Result{}, ErrInvalid }
	if at.IsZero() || at.UTC().Year() < 2000 || at.UTC().Year() > 9999 || len(response) == 0 || len(response) > maxCertificates || len(roots) == 0 || len(roots) > 4 {
		return bad()
	}
	total := 0
	for _, raw := range response {
		if len(raw) == 0 || len(raw) > maxCertificateBytes || len(raw) > maxResponseBytes-total {
			return bad()
		}
		total += len(raw)
	}
	request, err := acmecertrequest.Check(private, csr, names)
	if err != nil {
		return bad()
	}
	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return bad()
	}
	current := at.UTC()
	pool := x509.NewCertPool()
	for _, root := range roots {
		if root == nil || !root.NotBefore.Before(root.NotAfter) || len(root.UnhandledCriticalExtensions) != 0 || certverify.CheckCertificatePolicy(root) != nil || !boundedPublicKey(root) || !root.BasicConstraintsValid || !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 || !bytes.Equal(root.RawSubject, root.RawIssuer) || root.CheckSignatureFrom(root) != nil {
			return bad()
		}
		pool.AddCert(root)
	}
	certs := make([]*x509.Certificate, 0, len(response))
	seen := map[[sha256.Size]byte]bool{}
	for _, raw := range response {
		c, encoding, err := certinspect.Parse(raw)
		digest := sha256.Sum256(raw)
		if err != nil || encoding != certinspect.EncodingDER || !bytes.Equal(raw, c.Raw) || seen[digest] || !validMember(c, current) {
			return bad()
		}
		seen[digest] = true
		certs = append(certs, c)
	}
	leaf := certs[0]
	if leaf.IsCA || !explicitLeafKeyUsage(leaf) || !explicitServerUsage(leaf) || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, parsedCSR.RawSubjectPublicKeyInfo) || !exactDNS(leaf, names) || (leaf.Subject.CommonName != "" && !slices.Contains(names, leaf.Subject.CommonName)) {
		return bad()
	}
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		c := certs[i]
		if !c.BasicConstraintsValid || !c.IsCA || c.KeyUsage&x509.KeyUsageCertSign == 0 || !bytes.Equal(certs[i-1].RawIssuer, c.RawSubject) || certs[i-1].CheckSignatureFrom(c) != nil {
			return bad()
		}
		if bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil {
			if i != len(certs)-1 || !containsRoot(roots, c) {
				return bad()
			}
		} else {
			intermediates.AddCert(c)
		}
	}
	// DNSName deliberately empty: exact canonical SAN set was checked above.
	// x509 still enforces all SAN name constraints, including wildcard names.
	paths, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, CurrentTime: current,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, MaxConstraintComparisions: 10000})
	if err != nil {
		return bad()
	}
	for _, path := range paths {
		if !exactPath(certs, path, roots, current) {
			continue
		}
		out := Result{TestOnly: true, Fingerprint: fingerprint(leaf.Raw), PublicFingerprint: request.PublicFingerprint,
			RequestFingerprint: request.RequestFingerprint, DNSNames: slices.Clone(names), NotBefore: leaf.NotBefore.UTC(),
			NotAfter: leaf.NotAfter.UTC(), EvaluatedAt: current, ChainFingerprints: make([]string, len(path))}
		for i, c := range path {
			out.ChainFingerprints[i] = fingerprint(c.Raw)
		}
		return out, nil
	}
	return bad()
}

func validMember(c *x509.Certificate, at time.Time) bool {
	return c != nil && c.NotBefore.Before(c.NotAfter) && !at.Before(c.NotBefore) && at.Before(c.NotAfter) &&
		len(c.UnhandledCriticalExtensions) == 0 && certverify.CheckCertificatePolicy(c) == nil && boundedPublicKey(c)
}

// A small DER body can hold an enormous RSA modulus. Refuse before ANY
// response-member signature/path verification, not after modular arithmetic.
// Existing policy supplies the key floor/curve checks; this is a work ceiling.
func boundedPublicKey(c *x509.Certificate) bool {
	if key, ok := c.PublicKey.(*rsa.PublicKey); ok {
		return key != nil && key.N != nil && key.N.BitLen() <= 8192
	}
	return true
}

func explicitLeafKeyUsage(c *x509.Certificate) bool {
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 || c.KeyUsage & ^(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) != 0 {
		return false
	}
	for _, e := range c.Extensions {
		if !e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
			continue
		}
		// crypto/x509 reports only the nine known bits. Unknown extra bits must
		// not disappear from this closed issuance policy.
		var bits asn1.BitString
		rest, err := asn1.Unmarshal(e.Value, &bits)
		return err == nil && len(rest) == 0 && bits.BitLength > 0 && bits.BitLength <= 9
	}
	return false
}

func explicitServerUsage(c *x509.Certificate) bool {
	if len(c.UnknownExtKeyUsage) != 0 || !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return false
	}
	seen := map[x509.ExtKeyUsage]bool{}
	for _, u := range c.ExtKeyUsage {
		if seen[u] || (u != x509.ExtKeyUsageServerAuth && u != x509.ExtKeyUsageClientAuth) {
			return false
		}
		seen[u] = true
	}
	return true
}

func exactDNS(c *x509.Certificate, names []string) bool {
	actual := slices.Clone(c.DNSNames)
	slices.Sort(actual)
	if !slices.Equal(actual, names) || len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs) != 0 {
		return false
	}
	// crypto/x509 ignores certain non-DNS GeneralNames. Inspect the standard
	// ASN.1 values too, so their presence cannot silently widen this DNS request.
	for _, e := range c.Extensions {
		if !e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var values []asn1.RawValue
		rest, err := asn1.Unmarshal(e.Value, &values)
		if err != nil || len(rest) != 0 || len(values) != len(c.DNSNames) {
			return false
		}
		for i, v := range values {
			if v.Class != asn1.ClassContextSpecific || v.Tag != 2 || v.IsCompound || !bytes.Equal(v.Bytes, []byte(c.DNSNames[i])) {
				return false
			}
		}
		return true
	}
	return false
}

func containsRoot(roots []*x509.Certificate, c *x509.Certificate) bool {
	for _, r := range roots {
		if bytes.Equal(r.Raw, c.Raw) {
			return true
		}
	}
	return false
}

func exactPath(certs, path, roots []*x509.Certificate, at time.Time) bool {
	if len(path) < 2 || !containsRoot(roots, path[len(path)-1]) || (len(path) != len(certs) && len(path) != len(certs)+1) {
		return false
	}
	for i, c := range path {
		if !validMember(c, at) || (i < len(certs) && !bytes.Equal(c.Raw, certs[i].Raw)) {
			return false
		}
	}
	return true
}

func fingerprint(raw []byte) string {
	digest := sha256.Sum256(raw)
	encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
	parts := make([]string, 0, sha256.Size)
	for i := 0; i < len(encoded); i += 2 {
		parts = append(parts, encoded[i:i+2])
	}
	return strings.Join(parts, ":")
}
