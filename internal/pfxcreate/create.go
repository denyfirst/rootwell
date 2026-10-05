// Package pfxcreate creates a password-protected PKCS#12 file from one
// matching certificate/key and an optional ordered, public issuer chain.
// It does not establish trust or export an unencrypted key.
package pfxcreate

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/certverify"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/limits"
	"github.com/denyfirst/rootwell/internal/publicbundle"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var (
	ErrInvalidInput    = errors.New("PFX input is invalid")
	ErrInvalidChain    = errors.New("PFX issuer chain is invalid")
	ErrInvalidPassword = errors.New("PFX password does not meet policy")
	ErrEncodingFailed  = errors.New("PFX encoding failed")
)

const iterations = 100_000

// Create accepts only an unencrypted supported private key. Passwords must be
// printable ASCII, 20..128 bytes; callers must supply high-entropy values.
// A long human phrase is not guaranteed high entropy. Returned bytes are an
// encrypted secret container and must be cleared after writing.
func Create(certificateInput, keyInput, chainInput []byte, password string) ([]byte, error) {
	if !validPassword(password) {
		return nil, ErrInvalidPassword
	}
	if int64(len(keyInput)) > limits.MaxPrivateKeyBytes {
		return nil, ErrInvalidInput
	}
	var output []byte
	err := keymatch.WithPrivateKey(keyInput, func(key any, _ keymatch.Encoding) error {
		var createErr error
		output, createErr = CreateWithParsedKey(certificateInput, key, chainInput, password)
		return createErr
	})
	if err != nil {
		clear(output)
		if errors.Is(err, keymatch.ErrKeyMismatch) {
			return nil, keymatch.ErrKeyMismatch
		}
		if errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrInvalidChain) || errors.Is(err, ErrInvalidPassword) || errors.Is(err, ErrEncodingFailed) {
			return nil, err
		}
		return nil, ErrInvalidInput
	}
	return output, nil
}

// CreateWithParsedKey consumes a previously strict-validated private key for
// the duration of the call. It never retains it; the caller owns erasure.
// The certificate/key match and output round-trip are independently checked.
func CreateWithParsedKey(certificateInput []byte, key any, chainInput []byte, password string) ([]byte, error) {
	if !validPassword(password) {
		return nil, ErrInvalidPassword
	}
	if int64(len(certificateInput)) > limits.MaxInputBytes || int64(len(chainInput)) > limits.MaxInputBytes {
		return nil, ErrInvalidInput
	}
	leaf, _, err := certinspect.Parse(certificateInput)
	if err != nil || leaf.IsCA || certverify.CheckCertificatePolicy(leaf) != nil {
		return nil, ErrInvalidInput
	}
	issuers, err := parseIssuers(leaf, chainInput)
	if err != nil {
		return nil, err
	}
	switch value := key.(type) {
	case *rsa.PrivateKey:
		if value == nil || value.N == nil || value.N.BitLen() > limits.MaxPrivateKeyBits || value.Validate() != nil {
			return nil, ErrInvalidInput
		}
	case *ecdsa.PrivateKey:
		if value == nil {
			return nil, ErrInvalidInput
		}
		raw, err := value.Bytes()
		clear(raw)
		if err != nil {
			return nil, ErrInvalidInput
		}
		if _, err := value.PublicKey.Bytes(); err != nil {
			return nil, ErrInvalidInput
		}
	default:
		return nil, ErrInvalidInput
	}
	signer := key.(crypto.Signer)
	certSPKI, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, ErrInvalidInput
	}
	keySPKI, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, ErrInvalidInput
	}
	defer clear(keySPKI)
	if len(certSPKI) != len(keySPKI) || subtle.ConstantTimeCompare(certSPKI, keySPKI) != 1 {
		return nil, keymatch.ErrKeyMismatch
	}
	output, err := pkcs12.Modern2023.WithIterations(iterations).Encode(key, leaf, issuers, password)
	if err != nil {
		clear(output)
		return nil, ErrEncodingFailed
	}
	if len(output) == 0 || int64(len(output)) > limits.MaxInputBytes || !checkRoundTrip(output, password, leaf, issuers) {
		clear(output)
		return nil, ErrEncodingFailed
	}
	return output, nil
}

func validPassword(value string) bool {
	if len(value) < 20 || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// PasswordAllowed exposes the creation policy for pre-decryption validation
// at the browser boundary. It does not measure password entropy.
func PasswordAllowed(value string) bool { return validPassword(value) }

func parseIssuers(leaf *x509.Certificate, input []byte) ([]*x509.Certificate, error) {
	if len(input) == 0 {
		return nil, nil
	}
	entries, err := publicbundle.Parse(input)
	if err != nil || len(entries) > 16 {
		return nil, ErrInvalidChain
	}
	issuers := make([]*x509.Certificate, 0, len(entries))
	previous := leaf
	for _, entry := range entries {
		issuer, _, err := certinspect.Parse(entry.DER)
		if err != nil || !issuer.IsCA || certverify.CheckCertificatePolicy(issuer) != nil || bytes.Equal(issuer.Raw, leaf.Raw) || previous.CheckSignatureFrom(issuer) != nil || issuer.CheckSignatureFrom(issuer) == nil {
			return nil, ErrInvalidChain
		}
		issuers = append(issuers, issuer)
		previous = issuer
	}
	return issuers, nil
}

func checkRoundTrip(output []byte, password string, leaf *x509.Certificate, issuers []*x509.Certificate) bool {
	decodedKey, decodedLeaf, decodedIssuers, err := pkcs12.DecodeChain(output, password)
	if err != nil {
		return false
	}
	defer keymatch.ClearParsedKey(decodedKey)
	if decodedLeaf == nil || !bytes.Equal(decodedLeaf.Raw, leaf.Raw) || len(decodedIssuers) != len(issuers) {
		return false
	}
	for index := range issuers {
		if decodedIssuers[index] == nil || !bytes.Equal(decodedIssuers[index].Raw, issuers[index].Raw) {
			return false
		}
	}
	signer, ok := decodedKey.(crypto.Signer)
	if !ok {
		return false
	}
	decodedSPKI, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return false
	}
	leafSPKI, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	return err == nil && len(decodedSPKI) == len(leafSPKI) && subtle.ConstantTimeCompare(decodedSPKI, leafSPKI) == 1
}
