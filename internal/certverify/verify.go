// Package certverify verifies a TLS server certificate against explicit local
// trust anchors and intermediates. It performs no network access.
package certverify

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/certinspect"
)

var (
	ErrInvalidLeaf        = errors.New("leaf certificate is invalid")
	ErrLeafIsCA           = errors.New("leaf certificate is a certificate authority")
	ErrInvalidHostname    = errors.New("hostname is invalid")
	ErrInvalidCurrentTime = errors.New("verification time is invalid")
	ErrHostnameMismatch   = errors.New("hostname does not match certificate")
	ErrUnknownAuthority   = errors.New("certificate chain has no trusted authority")
	ErrExpired            = errors.New("certificate chain is expired")
	ErrNotYetValid        = errors.New("certificate chain is not yet valid")
	ErrIncompatibleUsage  = errors.New("certificate is not valid for TLS server use")
	ErrUnhandledCritical  = errors.New("certificate has an unhandled critical extension")
	ErrConstraintFailure  = errors.New("certificate chain violates constraints")
	ErrVerificationFailed = errors.New("certificate verification failed")
)

// Options contains every trust input used by Verify. No system trust roots are
// consulted, and an empty intermediate bundle means no intermediates.
type Options struct {
	TrustBundle        []byte
	IntermediateBundle []byte
	Hostname           string
	CurrentTime        time.Time
}

// CertificateSummary contains requested public metadata for one verified chain
// member. It cannot contain certificate or private-key bytes.
type CertificateSummary struct {
	Subject           string
	Issuer            string
	SHA256Fingerprint string
}

// Result is returned only after TLS server, hostname, chain, time, constraints,
// and Rootwell algorithm policy checks all succeed.
type Result struct {
	Hostname    string
	EvaluatedAt time.Time
	Chain       []CertificateSummary
}

// Verify validates one leaf against explicit self-signed trust anchors and an
// optional intermediate bundle for TLS server authentication.
func Verify(leafInput []byte, options Options) (Result, error) {
	if !validHostnameInput(options.Hostname) {
		return Result{}, ErrInvalidHostname
	}
	if options.CurrentTime.IsZero() {
		return Result{}, ErrInvalidCurrentTime
	}
	leaf, _, err := certinspect.Parse(leafInput)
	if err != nil {
		return Result{}, ErrInvalidLeaf
	}
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return Result{}, ErrLeafIsCA
	}
	if err := checkCertificatePolicy(leaf); err != nil {
		return Result{}, err
	}

	anchors, err := parseBundle(options.TrustBundle, bundleTrustAnchors)
	if err != nil {
		return Result{}, err
	}
	var intermediates []*x509.Certificate
	if len(options.IntermediateBundle) != 0 {
		intermediates, err = parseBundle(options.IntermediateBundle, bundleIntermediates)
		if err != nil {
			return Result{}, err
		}
	}
	if bundlesOverlap(anchors, intermediates) {
		return Result{}, ErrDuplicateCertificate
	}

	rootPool := x509.NewCertPool()
	for _, certificate := range anchors {
		rootPool.AddCert(certificate)
	}
	intermediatePool := x509.NewCertPool()
	for _, certificate := range intermediates {
		intermediatePool.AddCert(certificate)
	}
	currentTime := options.CurrentTime.UTC()
	chains, err := leaf.Verify(x509.VerifyOptions{
		DNSName:                   options.Hostname,
		Roots:                     rootPool,
		Intermediates:             intermediatePool,
		CurrentTime:               currentTime,
		KeyUsages:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		MaxConstraintComparisions: 10000,
	})
	if err != nil {
		return Result{}, classifyVerificationError(err, leaf, currentTime)
	}
	chain, err := selectPolicyCompliantChain(chains)
	if err != nil {
		return Result{}, err
	}
	result := Result{Hostname: options.Hostname, EvaluatedAt: currentTime}
	for _, certificate := range chain {
		result.Chain = append(result.Chain, CertificateSummary{
			Subject:           certificate.Subject.String(),
			Issuer:            certificate.Issuer.String(),
			SHA256Fingerprint: fingerprint(certificate.Raw),
		})
	}
	return result, nil
}

func validHostnameInput(hostname string) bool {
	if hostname == "" || len(hostname) > 253 || !utf8.ValidString(hostname) || strings.Contains(hostname, "*") {
		return false
	}
	for _, character := range []byte(hostname) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func classifyVerificationError(err error, leaf *x509.Certificate, currentTime time.Time) error {
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return ErrHostnameMismatch
	}
	var authorityError x509.UnknownAuthorityError
	if errors.As(err, &authorityError) {
		return ErrUnknownAuthority
	}
	var criticalError x509.UnhandledCriticalExtension
	if errors.As(err, &criticalError) {
		return ErrUnhandledCritical
	}
	var invalidError x509.CertificateInvalidError
	if errors.As(err, &invalidError) {
		switch invalidError.Reason {
		case x509.Expired:
			invalidCertificate := invalidError.Cert
			if invalidCertificate == nil {
				invalidCertificate = leaf
			}
			if currentTime.Before(invalidCertificate.NotBefore) {
				return ErrNotYetValid
			}
			return ErrExpired
		case x509.IncompatibleUsage, x509.CANotAuthorizedForExtKeyUsage:
			return ErrIncompatibleUsage
		default:
			return ErrConstraintFailure
		}
	}
	return ErrVerificationFailed
}

func selectPolicyCompliantChain(chains [][]*x509.Certificate) ([]*x509.Certificate, error) {
	if len(chains) == 0 {
		return nil, ErrVerificationFailed
	}
	sort.Slice(chains, func(left, right int) bool {
		if len(chains[left]) != len(chains[right]) {
			return len(chains[left]) < len(chains[right])
		}
		return chainIdentity(chains[left]) < chainIdentity(chains[right])
	})
	var firstPolicyError error
	for _, chain := range chains {
		compliant := true
		for _, certificate := range chain {
			if err := checkCertificatePolicy(certificate); err != nil {
				if firstPolicyError == nil {
					firstPolicyError = err
				}
				compliant = false
				break
			}
		}
		if compliant {
			return chain, nil
		}
	}
	return nil, firstPolicyError
}

func chainIdentity(chain []*x509.Certificate) string {
	var identity strings.Builder
	for _, certificate := range chain {
		digest := sha256.Sum256(certificate.Raw)
		identity.Write(digest[:])
	}
	return identity.String()
}

func fingerprint(raw []byte) string {
	digest := sha256.Sum256(raw)
	encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
	var output strings.Builder
	for index := 0; index < len(encoded); index += 2 {
		if index != 0 {
			output.WriteByte(':')
		}
		output.WriteString(encoded[index : index+2])
	}
	return output.String()
}
