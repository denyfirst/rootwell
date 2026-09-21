package certverify

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
)

var (
	ErrDisallowedSignatureAlgorithm = errors.New("certificate signature algorithm is disallowed")
	ErrDisallowedPublicKey          = errors.New("certificate public key is disallowed")
)

func checkCertificatePolicy(certificate *x509.Certificate) error {
	if !allowedSignatureAlgorithm(certificate.SignatureAlgorithm) {
		return ErrDisallowedSignatureAlgorithm
	}
	if !allowedPublicKey(certificate.PublicKey) {
		return ErrDisallowedPublicKey
	}
	return nil
}

func allowedSignatureAlgorithm(algorithm x509.SignatureAlgorithm) bool {
	switch algorithm {
	case x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS,
		x509.SHA384WithRSAPSS,
		x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
		x509.PureEd25519:
		return true
	default:
		return false
	}
}

func allowedPublicKey(publicKey any) bool {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return key != nil && key.N != nil && key.N.BitLen() >= 2048 && key.E >= 65537 && key.E%2 == 1
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil || key.Curve.Params() == nil {
			return false
		}
		switch key.Curve.Params().Name {
		case "P-256", "P-384", "P-521":
			return true
		default:
			return false
		}
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize
	default:
		return false
	}
}
