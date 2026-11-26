// Package websitechain diagnoses already-collected certificates.
// It has no network, filesystem, private-key or browser authority.
package websitechain

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
)

const Schema = "rootwell.website-chain.v2"
const MaxCertificates = 10
const MaxCertificateBytes = 128 << 10

// MaxSavedRoots bounds the roots a person saved in Certificates that one check
// may end at.
const MaxSavedRoots = 64

const maxNames = 20

var ErrInput = errors.New("certificate observation could not be analyzed")

// Finding levels: "failed" and "attention" change the verdict; a "note" only
// explains something that is fine.
type Finding struct {
	Code   string `json:"code"`
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Action string `json:"action"`
	// Certificates are the fingerprints this finding is about, so a page can
	// mark them in the chain.
	Certificates []string `json:"certificates"`
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
	// Use says why a sent certificate is there: "path" (the chain visitors
	// get), "older-path" (a second chain to an older root, for old devices),
	// "root" (a root the server sends although devices already have it) or
	// "unrelated" (part of no chain for this website).
	Use string `json:"use"`
	// Names are the names a website certificate covers (first 20).
	Names []string `json:"names,omitempty"`
}

// IssuerCheck names the actual server-sent child and candidate issuers by
// complete fingerprint. These are signature/CA-eligibility facts, not trust.
type IssuerCheck struct {
	Child      string   `json:"child"`
	Verified   []string `json:"verified"`
	Rejected   []string `json:"rejected"`
	SelfSigned bool     `json:"self_signed"`
}

type Report struct {
	Schema          string        `json:"schema_version"`
	Hostname        string        `json:"hostname"`
	Port            int           `json:"port"`
	Address         string        `json:"address"`
	TLS             string        `json:"tls_version"`
	ObservedAt      string        `json:"observed_at"`
	State           string        `json:"state"`
	Trusted         bool          `json:"trusted"` // complete current server-auth path, excluding hostname
	HostnameMatches bool          `json:"hostname_matches"`
	Path            []Certificate `json:"path"`
	Presented       []Certificate `json:"presented"`
	Findings        []Finding     `json:"findings"`
	// TrustSource is "public" (this server's system roots) or "saved" (a
	// root the person saved in Certificates); empty when nothing is trusted.
	TrustSource  string        `json:"trust_source"`
	SavedRoot    string        `json:"saved_root,omitempty"`
	Revocation   string        `json:"revocation"`
	IssuerChecks []IssuerCheck `json:"issuer_checks"`
}

// Analyze checks a chain against the given roots only.
func Analyze(chain []*x509.Certificate, roots *x509.CertPool, hostname string, now time.Time) (Report, error) {
	return AnalyzeWithSaved(chain, roots, nil, hostname, now)
}

// SavedRoot reports whether c may serve as a root a person saved: a
// self-signed certificate authority.
func SavedRoot(c *x509.Certificate) bool {
	return c != nil && c.IsCA && c.BasicConstraintsValid && bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

// AnalyzeWithSaved uses only the supplied roots, the saved roots and the
// presented intermediates. In production the caller is Linux, with an explicit
// local system root pool. Roots the server sends never become trust anchors;
// saved roots come only from the person's own Certificates.
func AnalyzeWithSaved(chain []*x509.Certificate, roots *x509.CertPool, saved []*x509.Certificate, hostname string, now time.Time) (Report, error) {
	if len(chain) == 0 || len(chain) > MaxCertificates || roots == nil || hostname == "" || len(hostname) > 253 || now.IsZero() || len(saved) > MaxSavedRoots {
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
	savedPool := x509.NewCertPool()
	savedCount := 0
	for _, c := range saved {
		if !SavedRoot(c) {
			return Report{}, ErrInput
		}
		savedPool.AddCert(c)
		savedCount++
	}
	r := Report{Schema: Schema, Hostname: hostname, ObservedAt: now.UTC().Format(time.RFC3339Nano),
		State: "verified", Path: []Certificate{}, Presented: []Certificate{}, Findings: []Finding{},
		Revocation: "not-checked", IssuerChecks: []IssuerCheck{}}
	fp := func(c *x509.Certificate) string { sum := sha256.Sum256(c.Raw); return hex.EncodeToString(sum[:]) }
	name := func(c *x509.Certificate) string { return displayName(c.Subject) }
	// At most 10*9 candidate checks, bounded by MaxCertificates above. Never
	// infer a signature from matching names, and never promote a sent root.
	for i, child := range chain {
		check := IssuerCheck{Child: fp(child), Verified: []string{}, Rejected: []string{}, SelfSigned: selfSigned(child)}
		for j, parent := range chain {
			if i == j || !bytes.Equal(child.RawIssuer, parent.RawSubject) {
				continue
			}
			if child.CheckSignatureFrom(parent) == nil {
				check.Verified = append(check.Verified, fp(parent))
			} else {
				check.Rejected = append(check.Rejected, fp(parent))
			}
		}
		r.IssuerChecks = append(r.IssuerChecks, check)
	}
	add := func(code, level, title, detail, action string, about ...*x509.Certificate) {
		f := Finding{code, level, title, detail, action, []string{}}
		for _, c := range about {
			f.Certificates = append(f.Certificates, fp(c))
		}
		r.Findings = append(r.Findings, f)
		switch {
		case level == "failed":
			r.State = "failed"
		case level == "attention" && r.State == "verified":
			r.State = "attention"
		}
	}
	leaf := chain[0]
	r.HostnameMatches = leaf.VerifyHostname(hostname) == nil
	if !r.HostnameMatches {
		covered := "It covers no names."
		if names := certificateNames(leaf); len(names) > 0 {
			shown := names
			if len(shown) > 6 {
				shown = append(slices.Clone(shown[:6]), fmt.Sprintf("and %d more", len(names)-6))
			}
			covered = "It covers " + strings.Join(shown, ", ") + "."
		}
		add("hostname", "failed", "The certificate does not cover "+hostname,
			"The server sent a certificate for other names. "+covered,
			"Install a certificate that includes "+hostname+". If the server hosts several sites, check which certificate it gives for this name.", leaf)
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	options := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	paths, verifyErr := leaf.Verify(options)
	if verifyErr == nil {
		r.TrustSource = "public"
	} else if savedCount > 0 {
		var unknown x509.UnknownAuthorityError
		if errors.As(verifyErr, &unknown) {
			options.Roots = savedPool
			savedPaths, savedErr := leaf.Verify(options)
			if savedErr == nil {
				paths, verifyErr = savedPaths, nil
				r.TrustSource = "saved"
			} else if !errors.As(savedErr, &unknown) {
				// A saved root reached the chain; its specific failure says more.
				verifyErr = savedErr
			}
		}
	}
	r.Trusted = verifyErr == nil
	var path []*x509.Certificate
	ambiguousIssuer := false
	if r.Trusted {
		path = paths[0]
		for _, p := range paths[1:] {
			if len(p) < len(path) {
				path = p
			}
		}
		if r.TrustSource == "saved" {
			r.SavedRoot = name(path[len(path)-1])
		}
	} else {
		// Show a link only when a candidate cryptographically signs the child.
		// Ambiguity is not resolved by certificate order or name alone.
		path = []*x509.Certificate{leaf}
		used := map[string]bool{string(leaf.Raw): true}
		for len(path) < MaxCertificates {
			child := path[len(path)-1]
			if selfSigned(child) {
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
	if !r.Trusted {
		reachesRoot := func(c *x509.Certificate) bool {
			for _, pool := range []*x509.CertPool{roots, savedPool} {
				if _, err := c.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
					return true
				}
			}
			return false
		}
		explainFailure(verifyErr, chain, path, ambiguousIssuer, now, reachesRoot, add)
	}
	// Certificates a failure above already names are not repeated below.
	named := map[string]bool{}
	for _, f := range r.Findings {
		for _, c := range f.Certificates {
			named[c] = true
		}
	}

	// Why each sent certificate is there. The chain visitors get comes first;
	// a certificate that links into it (another issuer's copy of a path
	// certificate, or an issuer of such a copy) belongs to an older chain.
	use := map[string]string{}
	for _, c := range path {
		if sentPosition(chain, c) > 0 {
			use[string(c.Raw)] = "path"
		}
	}
	linked := slices.Clone(path)
	for changed := true; changed; {
		changed = false
		for _, c := range chain[1:] {
			if use[string(c.Raw)] != "" {
				continue
			}
			for _, l := range linked {
				copyOf := bytes.Equal(c.RawSubject, l.RawSubject) && bytes.Equal(c.RawSubjectPublicKeyInfo, l.RawSubjectPublicKeyInfo)
				issuerOf := !selfSigned(l) && bytes.Equal(l.RawIssuer, c.RawSubject) && l.CheckSignatureFrom(c) == nil
				if copyOf || issuerOf {
					use[string(c.Raw)] = "older-path"
					linked = append(linked, c)
					changed = true
					break
				}
			}
		}
	}
	var older, sentRoots, unrelated, oldExpired []*x509.Certificate
	for _, c := range chain[1:] {
		switch {
		case use[string(c.Raw)] == "":
			use[string(c.Raw)] = "unrelated"
			if !named[fp(c)] {
				unrelated = append(unrelated, c)
			}
		case selfSigned(c):
			use[string(c.Raw)] = "root"
			sentRoots = append(sentRoots, c)
		case use[string(c.Raw)] == "older-path":
			older = append(older, c)
		}
		if use[string(c.Raw)] != "path" && use[string(c.Raw)] != "unrelated" && !inDate(c, now) {
			oldExpired = append(oldExpired, c)
		}
	}
	use[string(leaf.Raw)] = "path"

	selected := map[string]bool{}
	lastPosition := 0
	misordered := false
	for i, c := range path {
		role := "intermediate"
		if i == 0 {
			role = "leaf"
		} else if r.Trusted && i == len(path)-1 {
			role = "trust-anchor"
		} else if selfSigned(c) {
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
		d := describe(c, role, position, now)
		d.Use = "path"
		if i == 0 {
			d.Names = certificateNames(c)
		}
		r.Path = append(r.Path, d)
	}
	for i, c := range chain {
		role := "intermediate"
		if i == 0 {
			role = "leaf"
		}
		d := describe(c, role, i+1, now)
		d.Use = use[string(c.Raw)]
		if i == 0 {
			d.Names = certificateNames(c)
		}
		r.Presented = append(r.Presented, d)
	}

	if r.TrustSource == "saved" {
		root := path[len(path)-1]
		add("saved-root", "note", "Trusted through your own root "+quote(name(root)),
			"Rootwell found "+quote(name(root))+" among your saved certificates. Only devices that have this root installed trust this website; others show a warning.",
			"", root)
	}
	if len(unrelated) > 0 {
		names := quoteAll(unrelated)
		add("unrelated", "attention", "The server sends a certificate that does not belong here",
			names+" is not part of any chain for this website.",
			"Remove "+names+" from the server's certificate file. Visitors do not need it.", unrelated...)
	}
	if len(oldExpired) > 0 {
		names := quoteAll(oldExpired)
		add("extra-expired", "attention", "The server also sends an out-of-date certificate",
			names+" is outside its dates. Current browsers use the valid chain instead, but some older devices may fail.",
			"Remove "+names+" from the server's certificate file, or replace it with the current version from your certificate provider.", oldExpired...)
	}
	if len(older) > 0 {
		add("older-chain", "note", "The server also sends a chain for older devices",
			quoteAll(older)+" link this website to an older root, so devices without the newer root can still connect. This is fine.",
			"", older...)
	}
	if len(sentRoots) > 0 {
		add("sent-root", "note", "The server sends a root certificate",
			quoteAll(sentRoots)+" is a root. Devices already have their roots, so they do not need it from the server.",
			"You can remove it from the server's certificate file to make connections a little faster. It does no harm.", sentRoots...)
	}
	for _, c := range path {
		if inDate(c, now) && c.NotAfter.Sub(now) <= 30*24*time.Hour {
			days := int(c.NotAfter.Sub(now).Hours()/24) + 1
			when := fmt.Sprintf("in %d days", days)
			if days == 1 {
				when = "within a day"
			}
			add("expires-soon", "attention", quote(name(c))+" expires "+when,
				quote(name(c))+" ends on "+c.NotAfter.UTC().Format("2 January 2006")+".",
				"Replace it before that date. A website certificate is renewed with your certificate provider; an intermediate comes in the provider's current bundle.", c)
		}
	}
	for _, c := range chain {
		if selfSigned(c) || use[string(c.Raw)] == "unrelated" {
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
			add("weak-algorithm", "attention", quote(name(c))+" uses an outdated algorithm or a small key",
				"Browsers are dropping SHA-1 signatures and keys shorter than 2048 bits (RSA) or 256 bits (EC).",
				"Replace "+quote(name(c))+" with one that uses a modern key and SHA-256 or better.", c)
		}
	}
	if misordered {
		add("order", "attention", "The certificates are sent in the wrong order",
			"The chain could still be built, but some apps and older devices expect each certificate to be followed by its issuer.",
			"Put the website certificate first, then its intermediate, then any further intermediate, in the server's certificate file.")
	}
	return r, nil
}

// explainFailure names what stopped the chain, in the words a person needs to
// fix it. The path holds only links proven by signatures.
func explainFailure(verifyErr error, chain, path []*x509.Certificate, ambiguous bool, now time.Time, reachesRoot func(*x509.Certificate) bool, add func(code, level, title, detail, action string, about ...*x509.Certificate)) {
	leaf := chain[0]
	name := func(c *x509.Certificate) string { return quote(displayName(c.Subject)) }
	var invalid x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	if errors.As(verifyErr, &invalid) && invalid.Reason == x509.IncompatibleUsage {
		add("usage", "failed", "The certificate is not meant for websites",
			"It lacks the website (server authentication) use that browsers require.",
			"Ask the issuer for a certificate with the server authentication (TLS Web Server) use.", leaf)
		return
	}
	for _, c := range path {
		if inDate(c, now) {
			continue
		}
		if now.Before(c.NotBefore) {
			add("validity", "failed", name(c)+" is not valid yet",
				name(c)+" starts on "+c.NotBefore.UTC().Format("2 January 2006")+". Browsers refuse it until then.",
				"Check the date and time on the server, and that the newest certificate is installed.", c)
		} else {
			add("validity", "failed", name(c)+" has expired",
				name(c)+" ended on "+c.NotAfter.UTC().Format("2 January 2006")+". Browsers refuse the website.",
				"Install a current certificate. If the expired one is an intermediate, take the current bundle from your certificate provider.", c)
		}
		return
	}
	for _, c := range path[1:] {
		if !c.IsCA || !c.BasicConstraintsValid {
			add("not-a-ca", "failed", name(c)+" may not issue certificates",
				"The chain passes through "+name(c)+", which is not a certificate authority.",
				"Replace it with the intermediate that came with your certificate.", c)
			return
		}
	}
	if !errors.As(verifyErr, &unknown) {
		if errors.As(verifyErr, &invalid) && (invalid.Reason == x509.CANotAuthorizedForThisName || invalid.Reason == x509.CANotAuthorizedForExtKeyUsage) {
			add("constraints", "failed", "An issuer is not allowed to vouch for this certificate",
				"A certificate authority in the chain is limited to other names or uses.",
				"Ask the certificate authority that issued it for a certificate within its limits.")
			return
		}
		add("validation", "failed", "The chain could not be checked",
			"A signature, use, limit or algorithm in the chain is not accepted.",
			"Take the current certificate bundle from your certificate provider and install it again.")
		return
	}
	last := path[len(path)-1]
	switch {
	case selfSigned(leaf) && len(path) == 1:
		add("self-signed", "failed", "The website certificate is self-signed",
			"Nobody vouches for it, so browsers warn every visitor.",
			"Use a certificate from a certificate authority, such as Let's Encrypt or your company's own. If your company has its own root, add the root in Certificates.", leaf)
		return
	case ambiguous:
		add("issuer-ambiguous", "failed", "More than one sent issuer signs "+name(last),
			"Several certificates the server sends could each be the issuer of "+name(last)+", and none reaches a trusted root.",
			"Take the certificate bundle for this certificate from your certificate provider and install exactly that.", last)
		return
	case selfSigned(last):
		add("untrusted-root", "failed", "The chain ends at "+name(last)+", which is not a public root",
			"The chain is complete, but browsers do not know "+name(last)+". Only devices that have it installed trust this website.",
			"If "+name(last)+" is your company's root, add it in Certificates, and Rootwell will check against it. Otherwise, use a certificate from a public certificate authority.", last)
		return
	case reachesRoot(last):
		add("validation", "failed", "The chain could not be checked",
			"The certificates link up to a known root, but a limit or algorithm in the chain is not accepted.",
			"Take the current certificate bundle from your certificate provider and install it again.")
		return
	}
	issuer := quote(displayName(last.Issuer))
	var wrong []*x509.Certificate
	weak := false
	for _, c := range chain[1:] {
		if !bytes.Equal(last.RawIssuer, c.RawSubject) {
			continue
		}
		var insecure x509.InsecureAlgorithmError
		if err := last.CheckSignatureFrom(c); errors.As(err, &insecure) {
			weak = true
		} else if err != nil {
			wrong = append(wrong, c)
		}
	}
	switch {
	case weak:
		add("sha1", "failed", name(last)+" is signed with SHA-1, which browsers refuse",
			"SHA-1 signatures can be forged, so browsers no longer accept them.",
			"Replace "+name(last)+" with a certificate signed with SHA-256 or better; your certificate provider issues these.", last)
	case len(wrong) > 0:
		add("issuer-not-linked", "failed", "The server sends the wrong "+issuer,
			"The server sends a certificate named "+issuer+", but it did not sign "+name(last)+". The name is the same; the certificate is another one.",
			"Replace it with the "+issuer+" that belongs to this certificate: download the bundle for this certificate again from your certificate provider.", wrong...)
	default:
		add("missing-issuer", "failed", issuer+" is missing from the chain",
			name(last)+" was issued by "+issuer+". The server does not send "+issuer+", and it is not a root that Rootwell knows, so many browsers and apps cannot reach a trusted root.",
			"If "+issuer+" comes from your certificate provider, add it after "+name(last)+" in the server's certificate file; the provider's bundle (often called fullchain or ca-bundle) contains it. If "+issuer+" is your company's own certificate authority, add its root certificate in Certificates.", last)
	}
}

// selfSigned reports whether c signed itself. It checks only the signature,
// not whether c may sign others, and accepts a root's own SHA-1 signature:
// nobody relies on a root's self-signature.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func inDate(c *x509.Certificate, now time.Time) bool {
	return !now.Before(c.NotBefore) && !now.After(c.NotAfter)
}

func sentPosition(chain []*x509.Certificate, c *x509.Certificate) int {
	for i, candidate := range chain {
		if bytes.Equal(candidate.Raw, c.Raw) {
			return i + 1
		}
	}
	return 0
}

// certificateNames lists the DNS names and IP addresses a certificate covers.
func certificateNames(c *x509.Certificate) []string {
	names := []string{}
	for _, n := range c.DNSNames {
		if len(names) == maxNames {
			return names
		}
		names = append(names, safeText(n))
	}
	for _, ip := range c.IPAddresses {
		if len(names) == maxNames {
			return names
		}
		names = append(names, ip.String())
	}
	return names
}

func describe(c *x509.Certificate, role string, position int, now time.Time) Certificate {
	sum := sha256.Sum256(c.Raw)
	return Certificate{Fingerprint: hex.EncodeToString(sum[:]), Subject: displayName(c.Subject), Issuer: displayName(c.Issuer),
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339), NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
		Role: role, Sent: position != 0, Position: position, InDate: inDate(c, now)}
}

// displayName is the name a person recognises: the common name, else the
// organization, else its unit.
func displayName(n pkix.Name) string {
	for _, candidate := range append(append([]string{n.CommonName}, n.Organization...), n.OrganizationalUnit...) {
		if text := safeText(candidate); text != "Unnamed certificate" {
			return text
		}
	}
	return "Unnamed certificate"
}

func quote(s string) string { return "“" + s + "”" }

func quoteAll(cs []*x509.Certificate) string {
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, quote(displayName(c.Subject)))
	}
	if len(names) <= 2 {
		return strings.Join(names, " and ")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
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
