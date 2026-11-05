// Package websitechain diagnoses already-collected public certificates.
// It has no network, filesystem, private-key or browser authority.
package websitechain

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"
)

const Schema = "rootwell.website-chain.v1"
const MaxCertificates = 10
const MaxCertificateBytes = 128 << 10

var ErrInput = errors.New("certificate observation could not be analyzed")

type Finding struct {
	Code   string `json:"code"`
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Action string `json:"action"`
}

type Certificate struct {
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	Role        string `json:"role"`
	Sent        bool   `json:"sent"`
	Position    int    `json:"position"` // one-based server position, zero for local roots
	InDate      bool   `json:"in_date"`
}

type Report struct {
	Schema          string        `json:"schema_version"`
	Hostname        string        `json:"hostname"`
	Address         string        `json:"address"`
	TLS             string        `json:"tls_version"`
	ObservedAt      string        `json:"observed_at"`
	State           string        `json:"state"`
	Trusted         bool          `json:"trusted"` // complete current server-auth path, excluding hostname
	HostnameMatches bool          `json:"hostname_matches"`
	Path            []Certificate `json:"path"`
	Presented       []Certificate `json:"presented"`
	Findings        []Finding     `json:"findings"`
	TrustSource     string        `json:"trust_source"`
	Revocation      string        `json:"revocation"`
}

// Analyze uses only the supplied roots and presented intermediates. In
// production the caller is Linux, with an explicit local system root pool.
// Callers must never treat peer roots as trust anchors.
func Analyze(chain []*x509.Certificate, roots *x509.CertPool, hostname string, now time.Time) (Report, error) {
	if len(chain) == 0 || len(chain) > MaxCertificates || roots == nil || hostname == "" || len(hostname) > 253 || now.IsZero() {
		return Report{}, ErrInput
	}
	size := 0
	seen := map[string]bool{}
	for _, c := range chain {
		if c == nil || len(c.Raw) == 0 || len(c.Raw) > MaxCertificateBytes-size {
			return Report{}, ErrInput
		}
		size += len(c.Raw)
		if seen[string(c.Raw)] {
			return Report{}, ErrInput
		}
		seen[string(c.Raw)] = true
	}
	r := Report{Schema: Schema, Hostname: hostname, ObservedAt: now.UTC().Format(time.RFC3339Nano),
		State: "verified", Path: []Certificate{}, Presented: []Certificate{}, Findings: []Finding{},
		TrustSource: "Rootwell server system roots", Revocation: "not-checked"}
	add := func(code, level, title, detail, action string) {
		r.Findings = append(r.Findings, Finding{code, level, title, detail, action})
		if level == "failed" {
			r.State = "failed"
		} else if r.State == "verified" {
			r.State = "attention"
		}
	}
	leaf := chain[0]
	r.HostnameMatches = leaf.VerifyHostname(hostname) == nil
	if !r.HostnameMatches {
		add("hostname", "failed", "Certificate does not cover this name", "The requested hostname does not match the certificate names.", "Install a certificate covering this hostname and check the server's SNI configuration.")
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	paths, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	r.Trusted = verifyErr == nil
	var path []*x509.Certificate
	ambiguousIssuer := false
	if r.Trusted {
		path = paths[0]
	} else {
		var invalid x509.CertificateInvalidError
		var unknown x509.UnknownAuthorityError
		switch {
		case errors.As(verifyErr, &invalid) && invalid.Reason == x509.Expired:
			add("validity", "failed", "A certificate is outside its validity dates", "The site certificate or an issuer is expired or not yet valid.", "Check the dates below and the Rootwell server clock; install a current certificate chain.")
		case errors.As(verifyErr, &unknown):
			add("trust", "failed", "Chain does not reach a trusted root", "An issuer may be missing or unsuitable, or this Rootwell server may not trust the issuing CA.", "Check the CA's matching intermediate bundle. For an internal CA, also check your organization's trust configuration.")
		default:
			add("validation", "failed", "Certificate path could not be validated", "The presented chain fails signature, usage, constraints or supported-algorithm validation.", "Check the issuing CA's bundle and the certificate's server-auth usage.")
		}
		// Show a link only when a candidate cryptographically signs the child.
		// Ambiguity is not resolved by certificate order or name alone.
		path = []*x509.Certificate{leaf}
		used := map[string]bool{string(leaf.Raw): true}
		for len(path) < MaxCertificates {
			child := path[len(path)-1]
			if child.CheckSignatureFrom(child) == nil {
				break
			}
			var issuer *x509.Certificate
			count := 0
			for _, c := range chain[1:] {
				if !used[string(c.Raw)] && bytes.Equal(child.RawIssuer, c.RawSubject) && child.CheckSignatureFrom(c) == nil {
					issuer = c
					count++
				}
			}
			if count != 1 {
				ambiguousIssuer = count > 1
				break
			}
			path = append(path, issuer)
			used[string(issuer.Raw)] = true
		}
	}
	selected := map[string]bool{}
	lastPosition := 0
	misordered := false
	for i, c := range path {
		role := "intermediate"
		if i == 0 {
			role = "leaf"
		} else if r.Trusted && i == len(path)-1 {
			role = "trust-anchor"
		} else if c.CheckSignatureFrom(c) == nil {
			role = "root"
		}
		position := sentPosition(chain, c)
		if position > 0 {
			if position < lastPosition {
				misordered = true
			}
			lastPosition = position
		}
		selected[string(c.Raw)] = true
		r.Path = append(r.Path, describe(c, role, position, now))
	}
	if !r.Trusted {
		last := path[len(path)-1]
		if ambiguousIssuer {
			add("issuer-ambiguous", "failed", "More than one supplied issuer matches", "Several supplied CA certificates verify the same child's signature, but a trusted path was not established. The diagram stops before choosing an ambiguous issuer.", "Review the cross-signed alternatives and the intended trusted root. This does not by itself mean either issuer is incorrect.")
		} else if last.CheckSignatureFrom(last) != nil && len(path) == 1 {
			namedButInvalid := false
			for _, c := range chain[1:] {
				if bytes.Equal(leaf.RawIssuer, c.RawSubject) && leaf.CheckSignatureFrom(c) != nil {
					namedButInvalid = true
				}
			}
			if namedButInvalid {
				add("issuer-not-linked", "failed", "The supplied issuer does not verify this certificate", "An issuer name matches, but its signature or CA eligibility check fails. The name alone does not make it the correct intermediate.", "Replace it with the matching intermediate bundle provided by the CA for this certificate.")
			} else {
				add("issuer-not-linked", "failed", "No supplied issuer verifies the site certificate", "A matching issuer was not established from the server-sent certificates. An issuer can also be a root already in a client's trust store.", "Check whether the correct intermediate was installed. A matching CA name alone does not prove it is the right certificate.")
			}
		}
	}
	for i, c := range chain {
		role := "intermediate"
		if i == 0 {
			role = "leaf"
		}
		r.Presented = append(r.Presented, describe(c, role, i+1, now))
		if i > 0 && !selected[string(c.Raw)] {
			add("unused", "attention", "An additional certificate was sent", "One server-sent certificate is outside the displayed path. It may be an alternative chain or an unrelated certificate.", "Review the server-sent list before removing anything; cross-signed alternatives may be intentional.")
		}
		if !now.Before(c.NotBefore) && !now.After(c.NotAfter) && c.NotAfter.Sub(now) <= 30*24*time.Hour {
			add("expires-soon", "attention", "A certificate expires within 30 days", "Check the expiry dates in the chain.", "Plan replacement before the earliest required certificate expires.")
		}
		if c.CheckSignatureFrom(c) == nil {
			continue
		} // trust-anchor self-signatures are not path security
		weak := c.SignatureAlgorithm == x509.MD2WithRSA || c.SignatureAlgorithm == x509.MD5WithRSA || c.SignatureAlgorithm == x509.SHA1WithRSA || c.SignatureAlgorithm == x509.DSAWithSHA1 || c.SignatureAlgorithm == x509.ECDSAWithSHA1
		switch key := c.PublicKey.(type) {
		case *rsa.PublicKey:
			weak = weak || key.N.BitLen() < 2048
		case *ecdsa.PublicKey:
			weak = weak || key.Curve.Params().BitSize < 256
		}
		if weak {
			add("weak-algorithm", "attention", "A certificate uses an outdated algorithm or small key", "Path verification and modern algorithm suitability are separate checks.", "Replace the affected certificate with a modern CA-supported key and signature algorithm.")
		}
	}
	if misordered {
		add("order", "attention", "Server-sent order differs from the verified path", "A valid path was built by matching issuers. Some clients may handle the supplied order differently.", "Review the service's required bundle order: site certificate first, followed by its issuing intermediates.")
	}
	return r, nil
}

func sentPosition(chain []*x509.Certificate, c *x509.Certificate) int {
	for i, candidate := range chain {
		if bytes.Equal(candidate.Raw, c.Raw) {
			return i + 1
		}
	}
	return 0
}

func describe(c *x509.Certificate, role string, position int, now time.Time) Certificate {
	sum := sha256.Sum256(c.Raw)
	return Certificate{hex.EncodeToString(sum[:]), safeText(c.Subject.CommonName), safeText(c.Issuer.CommonName), c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339), role, position != 0, position, !now.Before(c.NotBefore) && !now.After(c.NotAfter)}
}

func safeText(s string) string {
	var out strings.Builder
	count := 0
	for _, r := range s {
		if count >= 120 {
			break
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			continue
		}
		out.WriteRune(r)
		count++
	}
	if strings.TrimSpace(out.String()) == "" {
		return "Unnamed certificate"
	}
	return out.String()
}
