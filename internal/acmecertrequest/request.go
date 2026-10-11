// Package acmecertrequest creates bounded offline exact-DNS certificate requests.
// It grants no network, trust, signing service or certificate issuance capability.
package acmecertrequest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"slices"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/csrworkbench"
)

var ErrInvalid = errors.New("certificate request could not be safely prepared")

// Create returns owned secret PKCS#8 bytes and public DER CSR; callers clear
// the key after sealing. Standard X.509 signing and the existing strict parser
// recheck every output. No private key is intended for public serialization.
func Create(names []string) ([]byte, []byte, csrworkbench.Summary, error) {
	if !acmeorder.CanonicalNames(names) {
		return nil, nil, csrworkbench.Summary{}, ErrInvalid
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, csrworkbench.Summary{}, ErrInvalid
	}
	private, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		clear(private)
		return nil, nil, csrworkbench.Summary{}, ErrInvalid
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: slices.Clone(names)}, signer)
	if err != nil {
		clear(private)
		return nil, nil, csrworkbench.Summary{}, ErrInvalid
	}
	summary, err := Check(private, csr, names)
	if err != nil {
		clear(private)
		clear(csr)
		return nil, nil, csrworkbench.Summary{}, ErrInvalid
	}
	return private, csr, summary, nil
}

func Check(private, csr []byte, names []string) (csrworkbench.Summary, error) {
	bad := func() (csrworkbench.Summary, error) { return csrworkbench.Summary{}, ErrInvalid }
	if len(private) == 0 || len(private) > 512 || len(csr) == 0 || len(csr) > 4096 || !acmeorder.CanonicalNames(names) {
		return bad()
	}
	parsed, err := x509.ParsePKCS8PrivateKey(private)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return bad()
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(key)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, private) {
		return bad()
	}
	summary, err := csrworkbench.Inspect(csr)
	if err != nil || summary.InputFormat != "der" || !slices.Equal(summary.DNSNames, names) || len(summary.IPAddresses) != 0 {
		return bad()
	}
	r, err := x509.ParseCertificateRequest(csr)
	public, pubErr := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || pubErr != nil || !bytes.Equal(public, r.RawSubjectPublicKeyInfo) || r.Subject.String() != "" || r.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return bad()
	}
	return summary, nil
}
