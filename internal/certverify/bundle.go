package certverify

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/limits"
)

var (
	ErrInvalidTrustBundle        = errors.New("trust bundle is invalid")
	ErrInvalidIntermediateBundle = errors.New("intermediate bundle is invalid")
	ErrBundleResourceLimit       = errors.New("certificate bundle exceeds a resource limit")
	ErrDuplicateCertificate      = errors.New("certificate bundle contains a duplicate")
	ErrRootNotCA                 = errors.New("trust anchor is not a certificate authority")
	ErrRootNotSelfSigned         = errors.New("trust anchor is not self-signed")
	ErrIntermediateNotCA         = errors.New("intermediate is not a certificate authority")
	ErrIntermediateSelfSigned    = errors.New("intermediate must not be self-signed")
)

type bundleRole int

const (
	bundleTrustAnchors bundleRole = iota
	bundleIntermediates
)

// ParseTrustAnchors exposes the exact strict, bounded trust-bundle policy to
// separately reviewed network clients. Callers must still select their own
// authenticated trust anchor and apply Verify to any observed server chain.
func ParseTrustAnchors(input []byte) ([]*x509.Certificate, error) {
	return parseBundle(input, bundleTrustAnchors)
}

func parseBundle(input []byte, role bundleRole) ([]*x509.Certificate, error) {
	invalidError := ErrInvalidTrustBundle
	if role == bundleIntermediates {
		invalidError = ErrInvalidIntermediateBundle
	}
	if len(input) == 0 {
		return nil, invalidError
	}
	if int64(len(input)) > limits.MaxInputBytes {
		return nil, ErrBundleResourceLimit
	}

	remaining := bytes.TrimSpace(input)
	certificates := make([]*x509.Certificate, 0, 1)
	seen := make(map[[sha256.Size]byte]struct{})
	for len(remaining) != 0 {
		if len(certificates) == limits.MaxCertificatesPerBundle {
			return nil, ErrBundleResourceLimit
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, invalidError
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, invalidError
		}
		certificate, _, err := certinspect.Parse(block.Bytes)
		if err != nil {
			return nil, invalidError
		}
		digest := sha256.Sum256(certificate.Raw)
		if _, exists := seen[digest]; exists {
			return nil, ErrDuplicateCertificate
		}
		seen[digest] = struct{}{}

		if err := validateBundleCertificate(certificate, role); err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
		remaining = bytes.TrimSpace(rest)
	}
	if len(certificates) == 0 {
		return nil, invalidError
	}
	return certificates, nil
}

func validateBundleCertificate(certificate *x509.Certificate, role bundleRole) error {
	if !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		if role == bundleTrustAnchors {
			return ErrRootNotCA
		}
		return ErrIntermediateNotCA
	}
	selfIssued := bytes.Equal(certificate.RawSubject, certificate.RawIssuer)
	if role == bundleTrustAnchors {
		if !selfIssued || certificate.CheckSignatureFrom(certificate) != nil {
			return ErrRootNotSelfSigned
		}
		return nil
	}
	if selfIssued {
		return ErrIntermediateSelfSigned
	}
	return nil
}

func bundlesOverlap(left, right []*x509.Certificate) bool {
	seen := make(map[[sha256.Size]byte]struct{}, len(left))
	for _, certificate := range left {
		seen[sha256.Sum256(certificate.Raw)] = struct{}{}
	}
	for _, certificate := range right {
		if _, exists := seen[sha256.Sum256(certificate.Raw)]; exists {
			return true
		}
	}
	return false
}
