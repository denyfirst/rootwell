package certverify

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
)

func TestAllowedSignatureAlgorithms(t *testing.T) {
	allowed := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.PureEd25519,
	}
	for _, algorithm := range allowed {
		if !allowedSignatureAlgorithm(algorithm) {
			t.Errorf("algorithm %v was rejected", algorithm)
		}
	}
	for _, algorithm := range []x509.SignatureAlgorithm{x509.UnknownSignatureAlgorithm, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.DSAWithSHA256} {
		if allowedSignatureAlgorithm(algorithm) {
			t.Errorf("algorithm %v was accepted", algorithm)
		}
	}
}

func TestAllowedPublicKeys(t *testing.T) {
	tests := []struct {
		name string
		key  any
		want bool
	}{
		{name: "RSA 2048", key: &rsa.PublicKey{N: modulusWithBits(2048), E: 65537}, want: true},
		{name: "RSA 1024", key: &rsa.PublicKey{N: modulusWithBits(1024), E: 65537}},
		{name: "RSA small exponent", key: &rsa.PublicKey{N: modulusWithBits(2048), E: 3}},
		{name: "RSA even exponent", key: &rsa.PublicKey{N: modulusWithBits(2048), E: 65538}},
		{name: "P-256", key: &ecdsa.PublicKey{Curve: elliptic.P256()}, want: true},
		{name: "P-384", key: &ecdsa.PublicKey{Curve: elliptic.P384()}, want: true},
		{name: "P-521", key: &ecdsa.PublicKey{Curve: elliptic.P521()}, want: true},
		{name: "P-224", key: &ecdsa.PublicKey{Curve: elliptic.P224()}},
		{name: "nil ECDSA", key: (*ecdsa.PublicKey)(nil)},
		{name: "Ed25519", key: make(ed25519.PublicKey, ed25519.PublicKeySize), want: true},
		{name: "short Ed25519", key: make(ed25519.PublicKey, ed25519.PublicKeySize-1)},
		{name: "unknown", key: struct{}{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := allowedPublicKey(test.key); got != test.want {
				t.Fatalf("allowedPublicKey() = %t, want %t", got, test.want)
			}
		})
	}
}

func modulusWithBits(bits int) *big.Int {
	return new(big.Int).SetBit(new(big.Int), bits-1, 1)
}
