// Package keymatch determines whether one private key corresponds to one
// X.509 certificate without exposing private-key material.
package keymatch

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/limits"
)

var (
	ErrInvalidCertificate          = errors.New("certificate is invalid")
	ErrEmptyPrivateKey             = errors.New("private key input is empty")
	ErrPrivateKeyTooLarge          = errors.New("private key input exceeds size limit")
	ErrUnsupportedPrivateKeyFormat = errors.New("private key encoding is unsupported")
	ErrEncryptedPrivateKey         = errors.New("encrypted private keys are unsupported")
	ErrInvalidPrivateKey           = errors.New("private key is invalid")
	ErrUnsupportedPrivateKey       = errors.New("private key algorithm is unsupported")
	ErrPrivateKeyResourceLimit     = errors.New("private key exceeds resource limit")
)

var rsaEncryptionOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
var ecPublicKeyOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
var ed25519OID = asn1.ObjectIdentifier{1, 3, 101, 112}

// Encoding identifies the exact accepted private-key container.
type Encoding string

const (
	EncodingPKCS8PEM Encoding = "pkcs8-pem"
	EncodingPKCS8DER Encoding = "pkcs8-der"
	EncodingPKCS1PEM Encoding = "pkcs1-pem"
	EncodingPKCS1DER Encoding = "pkcs1-der"
	EncodingSEC1PEM  Encoding = "sec1-pem"
	EncodingSEC1DER  Encoding = "sec1-der"
)

// Result contains only public metadata derived from the certificate and key.
type Result struct {
	Match                   bool
	CertificateEncoding     certinspect.Encoding
	PrivateKeyEncoding      Encoding
	CertificateKeyAlgorithm string
	PrivateKeyAlgorithm     string
	PublicKeyBits           int
	PublicKeyCurve          string
	PublicKeySHA256         string
}

// Match parses exactly one certificate and exactly one unencrypted private
// key, then compares canonical SubjectPublicKeyInfo values in constant time.
// Parsing success is not an algorithm-strength or certificate-trust verdict.
func Match(certificateInput, privateKeyInput []byte) (result Result, err error) {
	certificate, certificateEncoding, parseErr := certinspect.Parse(certificateInput)
	if parseErr != nil {
		return Result{}, ErrInvalidCertificate
	}

	privateKey, privateKeyEncoding, parseErr := parsePrivateKey(privateKeyInput)
	if parseErr != nil {
		return Result{}, parseErr
	}
	defer destroyPrivateKey(privateKey)

	privatePublicKey, ok := publicKey(privateKey)
	if !ok {
		return Result{}, ErrUnsupportedPrivateKey
	}
	certificateSPKI, marshalErr := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if marshalErr != nil {
		return Result{}, ErrInvalidCertificate
	}
	privateSPKI, marshalErr := x509.MarshalPKIXPublicKey(privatePublicKey)
	if marshalErr != nil {
		return Result{}, ErrInvalidPrivateKey
	}
	defer clear(privateSPKI)

	digest := sha256.Sum256(privateSPKI)
	bits, curve := publicKeyDetails(privatePublicKey)
	return Result{
		Match:                   len(certificateSPKI) == len(privateSPKI) && subtle.ConstantTimeCompare(certificateSPKI, privateSPKI) == 1,
		CertificateEncoding:     certificateEncoding,
		PrivateKeyEncoding:      privateKeyEncoding,
		CertificateKeyAlgorithm: certificate.PublicKeyAlgorithm.String(),
		PrivateKeyAlgorithm:     privateKeyAlgorithm(privateKey),
		PublicKeyBits:           bits,
		PublicKeyCurve:          curve,
		PublicKeySHA256:         colonHex(digest[:]),
	}, nil
}

func parsePrivateKey(input []byte) (any, Encoding, error) {
	if len(input) == 0 {
		return nil, "", ErrEmptyPrivateKey
	}
	if int64(len(input)) > limits.MaxPrivateKeyBytes {
		return nil, "", ErrPrivateKeyTooLarge
	}

	trimmed := bytes.TrimSpace(input)
	if len(trimmed) == 0 {
		return nil, "", ErrEmptyPrivateKey
	}
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		block, rest := pem.Decode(trimmed)
		if block == nil {
			return nil, "", ErrInvalidPrivateKey
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			clear(block.Bytes)
			return nil, "", ErrInvalidPrivateKey
		}
		defer clear(block.Bytes)
		if block.Type == "ENCRYPTED PRIVATE KEY" || legacyPEMEncryption(block.Headers) {
			return nil, "", ErrEncryptedPrivateKey
		}
		if len(block.Headers) != 0 {
			return nil, "", ErrInvalidPrivateKey
		}
		switch block.Type {
		case "PRIVATE KEY":
			return parsePKCS8(block.Bytes, EncodingPKCS8PEM)
		case "RSA PRIVATE KEY":
			return parsePKCS1(block.Bytes, EncodingPKCS1PEM)
		case "EC PRIVATE KEY":
			return parseSEC1(block.Bytes, EncodingSEC1PEM)
		default:
			return nil, "", ErrUnsupportedPrivateKeyFormat
		}
	}

	return parseDER(input)
}

func legacyPEMEncryption(headers map[string]string) bool {
	return headers["DEK-Info"] != "" || strings.Contains(strings.ToUpper(headers["Proc-Type"]), "ENCRYPTED")
}

func parseDER(der []byte) (any, Encoding, error) {
	fields, err := privateKeyFields(der)
	if err != nil {
		return nil, "", err
	}
	if len(fields) < 2 {
		return nil, "", ErrInvalidPrivateKey
	}
	switch {
	case isUniversal(fields[1], asn1.TagSequence):
		return parsePKCS8(der, EncodingPKCS8DER)
	case isUniversal(fields[1], asn1.TagInteger):
		return parsePKCS1(der, EncodingPKCS1DER)
	case isUniversal(fields[1], asn1.TagOctetString):
		return parseSEC1(der, EncodingSEC1DER)
	default:
		return nil, "", ErrInvalidPrivateKey
	}
}

func parsePKCS8(der []byte, encoding Encoding) (any, Encoding, error) {
	fields, err := privateKeyFields(der)
	if err != nil || len(fields) != 3 || !isUniversal(fields[0], asn1.TagInteger) ||
		!isUniversal(fields[1], asn1.TagSequence) || !isUniversal(fields[2], asn1.TagOctetString) {
		return nil, "", ErrInvalidPrivateKey
	}
	if version, ok := integerValue(fields[0]); !ok || version != 0 {
		return nil, "", ErrInvalidPrivateKey
	}
	algorithm, err := validatePKCS8Algorithm(fields[1].Bytes)
	if err != nil {
		return nil, "", err
	}
	var embeddedECFields []asn1.RawValue
	switch {
	case algorithm.Equal(rsaEncryptionOID):
		if err := validatePKCS1Structure(fields[2].Bytes); err != nil {
			return nil, "", err
		}
	case algorithm.Equal(ecPublicKeyOID):
		embeddedECFields, err = validateSEC1Structure(fields[2].Bytes)
		if err != nil {
			return nil, "", err
		}
		outerCurve := ecAlgorithmCurve(fields[1].Bytes)
		if innerCurve, present := sec1NamedCurve(embeddedECFields); present && !innerCurve.Equal(outerCurve) {
			return nil, "", ErrInvalidPrivateKey
		}
	}
	if rsaBits, ok := rsaModulusBits(der); ok && rsaBits > limits.MaxPrivateKeyBits {
		return nil, "", ErrPrivateKeyResourceLimit
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, "", ErrInvalidPrivateKey
	}
	if err := validatePrivateKey(key); err != nil {
		destroyPrivateKey(key)
		return nil, "", err
	}
	if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
		if err := validateEmbeddedECPublic(embeddedECFields, ecdsaKey); err != nil {
			destroyPrivateKey(key)
			return nil, "", err
		}
	}
	return key, encoding, nil
}

func parsePKCS1(der []byte, encoding Encoding) (any, Encoding, error) {
	if err := validatePKCS1Structure(der); err != nil {
		return nil, "", err
	}
	if rsaBits, ok := rsaModulusBits(der); ok && rsaBits > limits.MaxPrivateKeyBits {
		return nil, "", ErrPrivateKeyResourceLimit
	}
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, "", ErrInvalidPrivateKey
	}
	if err := validatePrivateKey(key); err != nil {
		destroyPrivateKey(key)
		return nil, "", err
	}
	return key, encoding, nil
}

func validatePKCS1Structure(der []byte) error {
	fields, err := privateKeyFields(der)
	if err != nil || (len(fields) != 9 && len(fields) != 10) {
		return ErrInvalidPrivateKey
	}
	for _, field := range fields[:9] {
		if !isUniversal(field, asn1.TagInteger) {
			return ErrInvalidPrivateKey
		}
	}
	if len(fields) == 10 && !isUniversal(fields[9], asn1.TagSequence) {
		return ErrInvalidPrivateKey
	}
	version, ok := integerValue(fields[0])
	if !ok || version != len(fields)-9 {
		return ErrInvalidPrivateKey
	}
	return nil
}

func parseSEC1(der []byte, encoding Encoding) (any, Encoding, error) {
	fields, err := validateSEC1Structure(der)
	if err != nil {
		return nil, "", err
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, "", ErrInvalidPrivateKey
	}
	if err := validatePrivateKey(key); err != nil {
		destroyPrivateKey(key)
		return nil, "", err
	}
	if err := validateEmbeddedECPublic(fields, key); err != nil {
		destroyPrivateKey(key)
		return nil, "", err
	}
	return key, encoding, nil
}

func validateSEC1Structure(der []byte) ([]asn1.RawValue, error) {
	fields, err := privateKeyFields(der)
	if err != nil || len(fields) < 2 || len(fields) > 4 ||
		!isUniversal(fields[0], asn1.TagInteger) || !isUniversal(fields[1], asn1.TagOctetString) {
		return nil, ErrInvalidPrivateKey
	}
	if version, ok := integerValue(fields[0]); !ok || version != 1 {
		return nil, ErrInvalidPrivateKey
	}
	next := 2
	if next < len(fields) && fields[next].Class == asn1.ClassContextSpecific && fields[next].Tag == 0 && fields[next].IsCompound {
		var curve asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(fields[next].Bytes, &curve)
		if err != nil || len(rest) != 0 {
			return nil, ErrInvalidPrivateKey
		}
		next++
	}
	if next < len(fields) && fields[next].Class == asn1.ClassContextSpecific && fields[next].Tag == 1 && fields[next].IsCompound {
		var embedded asn1.BitString
		rest, err := asn1.Unmarshal(fields[next].Bytes, &embedded)
		if err != nil || len(rest) != 0 || embedded.BitLength != len(embedded.Bytes)*8 {
			return nil, ErrInvalidPrivateKey
		}
		next++
	}
	if next != len(fields) {
		return nil, ErrInvalidPrivateKey
	}
	return fields, nil
}

func validateEmbeddedECPublic(fields []asn1.RawValue, key *ecdsa.PrivateKey) error {
	if key == nil {
		return ErrInvalidPrivateKey
	}
	for _, field := range fields[2:] {
		if field.Class != asn1.ClassContextSpecific || field.Tag != 1 {
			continue
		}
		var embedded asn1.BitString
		rest, err := asn1.Unmarshal(field.Bytes, &embedded)
		if err != nil || len(rest) != 0 || embedded.BitLength != len(embedded.Bytes)*8 {
			return ErrInvalidPrivateKey
		}
		public, err := key.PublicKey.ECDH()
		if err != nil {
			return ErrInvalidPrivateKey
		}
		expected := public.Bytes()
		defer clear(expected)
		if len(expected) != len(embedded.Bytes) || subtle.ConstantTimeCompare(expected, embedded.Bytes) != 1 {
			return ErrInvalidPrivateKey
		}
	}
	return nil
}

func ecAlgorithmCurve(input []byte) asn1.ObjectIdentifier {
	var algorithm asn1.ObjectIdentifier
	parameters, _ := asn1.Unmarshal(input, &algorithm)
	var curve asn1.ObjectIdentifier
	_, _ = asn1.Unmarshal(parameters, &curve)
	return curve
}

func sec1NamedCurve(fields []asn1.RawValue) (asn1.ObjectIdentifier, bool) {
	for _, field := range fields[2:] {
		if field.Class == asn1.ClassContextSpecific && field.Tag == 0 {
			var curve asn1.ObjectIdentifier
			_, _ = asn1.Unmarshal(field.Bytes, &curve)
			return curve, true
		}
	}
	return nil, false
}

func privateKeyFields(der []byte) ([]asn1.RawValue, error) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(der, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return nil, ErrInvalidPrivateKey
	}
	contents := sequence.Bytes
	fields := make([]asn1.RawValue, 0, 10)
	for len(contents) != 0 {
		if len(fields) == 10 {
			return nil, ErrInvalidPrivateKey
		}
		var field asn1.RawValue
		contents, err = asn1.Unmarshal(contents, &field)
		if err != nil {
			return nil, ErrInvalidPrivateKey
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func isUniversal(value asn1.RawValue, tag int) bool {
	return value.Class == asn1.ClassUniversal && value.Tag == tag
}

func integerValue(value asn1.RawValue) (int, bool) {
	var number int
	rest, err := asn1.Unmarshal(value.FullBytes, &number)
	return number, err == nil && len(rest) == 0
}

func validatePKCS8Algorithm(input []byte) (asn1.ObjectIdentifier, error) {
	var identifier asn1.ObjectIdentifier
	parameters, err := asn1.Unmarshal(input, &identifier)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}
	switch {
	case identifier.Equal(rsaEncryptionOID):
		if !bytes.Equal(parameters, []byte{0x05, 0x00}) {
			return nil, ErrInvalidPrivateKey
		}
	case identifier.Equal(ecPublicKeyOID):
		var curve asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(parameters, &curve)
		if err != nil || len(rest) != 0 {
			return nil, ErrInvalidPrivateKey
		}
	case identifier.Equal(ed25519OID):
		if len(parameters) != 0 {
			return nil, ErrInvalidPrivateKey
		}
	default:
		return nil, ErrUnsupportedPrivateKey
	}
	return identifier, nil
}

// rsaModulusBits performs a shallow PKCS#1/PKCS#8 size preflight before the
// standard library does private-key arithmetic. It is not a validity parser;
// the x509 package remains authoritative for the complete key structure.
func rsaModulusBits(der []byte) (int, bool) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(der, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return 0, false
	}

	contents := sequence.Bytes
	var version asn1.RawValue
	contents, err = unmarshalRaw(contents, &version)
	if err != nil || version.Class != asn1.ClassUniversal || version.Tag != asn1.TagInteger {
		return 0, false
	}
	var second asn1.RawValue
	contents, err = unmarshalRaw(contents, &second)
	if err != nil || second.Class != asn1.ClassUniversal {
		return 0, false
	}
	if second.Tag == asn1.TagInteger {
		return positiveIntegerBits(second.Bytes), true
	}
	if second.Tag != asn1.TagSequence || !second.IsCompound || !algorithmIsRSA(second.Bytes) {
		return 0, false
	}

	var privateKey asn1.RawValue
	_, err = unmarshalRaw(contents, &privateKey)
	if err != nil || privateKey.Class != asn1.ClassUniversal || privateKey.Tag != asn1.TagOctetString {
		return 0, false
	}
	return rsaPKCS1ModulusBits(privateKey.Bytes)
}

func rsaPKCS1ModulusBits(der []byte) (int, bool) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(der, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return 0, false
	}
	contents := sequence.Bytes
	var version asn1.RawValue
	contents, err = unmarshalRaw(contents, &version)
	if err != nil || version.Class != asn1.ClassUniversal || version.Tag != asn1.TagInteger {
		return 0, false
	}
	var modulus asn1.RawValue
	_, err = unmarshalRaw(contents, &modulus)
	if err != nil || modulus.Class != asn1.ClassUniversal || modulus.Tag != asn1.TagInteger {
		return 0, false
	}
	return positiveIntegerBits(modulus.Bytes), true
}

func unmarshalRaw(input []byte, destination *asn1.RawValue) ([]byte, error) {
	rest, err := asn1.Unmarshal(input, destination)
	return rest, err
}

func algorithmIsRSA(input []byte) bool {
	var identifier asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(input, &identifier)
	return err == nil && identifier.Equal(rsaEncryptionOID)
}

func positiveIntegerBits(encoded []byte) int {
	for len(encoded) > 1 && encoded[0] == 0 {
		encoded = encoded[1:]
	}
	if len(encoded) == 0 {
		return 0
	}
	leading := 0
	for mask := byte(0x80); mask != 0 && encoded[0]&mask == 0; mask >>= 1 {
		leading++
	}
	return len(encoded)*8 - leading
}

func validatePrivateKey(key any) error {
	switch value := key.(type) {
	case *rsa.PrivateKey:
		if value == nil || value.N == nil || value.N.BitLen() > limits.MaxPrivateKeyBits {
			return ErrPrivateKeyResourceLimit
		}
		if err := value.Validate(); err != nil {
			return ErrInvalidPrivateKey
		}
		return nil
	case *ecdsa.PrivateKey:
		if value == nil || value.Curve == nil || value.Curve.Params() == nil || value.Curve.Params().BitSize > limits.MaxPrivateKeyBits {
			return ErrInvalidPrivateKey
		}
		raw, err := value.Bytes()
		if err != nil {
			return ErrInvalidPrivateKey
		}
		clear(raw)
		return nil
	case ed25519.PrivateKey:
		if len(value) != ed25519.PrivateKeySize {
			return ErrInvalidPrivateKey
		}
		return nil
	default:
		return ErrUnsupportedPrivateKey
	}
}

func publicKey(key any) (crypto.PublicKey, bool) {
	signer, ok := key.(crypto.Signer)
	if !ok || signer == nil {
		return nil, false
	}
	return signer.Public(), true
}

func privateKeyAlgorithm(key any) string {
	switch key.(type) {
	case *rsa.PrivateKey:
		return "RSA"
	case *ecdsa.PrivateKey:
		return "ECDSA"
	case ed25519.PrivateKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}

func publicKeyDetails(key any) (int, string) {
	switch value := key.(type) {
	case *rsa.PublicKey:
		if value != nil && value.N != nil {
			return value.N.BitLen(), ""
		}
	case *ecdsa.PublicKey:
		if value != nil && value.Curve != nil && value.Curve.Params() != nil {
			return value.Curve.Params().BitSize, value.Curve.Params().Name
		}
	case ed25519.PublicKey:
		return len(value) * 8, ""
	}
	return 0, ""
}

func destroyPrivateKey(key any) {
	switch value := key.(type) {
	case *rsa.PrivateKey:
		if value == nil {
			return
		}
		if value.D != nil {
			value.D.SetInt64(0)
		}
		for _, prime := range value.Primes {
			if prime != nil {
				prime.SetInt64(0)
			}
		}
		for _, item := range []*big.Int{value.Precomputed.Dp, value.Precomputed.Dq, value.Precomputed.Qinv} {
			if item != nil {
				item.SetInt64(0)
			}
		}
		//lint:ignore SA1019 Clearing legacy exported CRT fields is required for best-effort erasure.
		for _, item := range value.Precomputed.CRTValues {
			for _, component := range []*big.Int{item.Exp, item.Coeff, item.R} {
				if component != nil {
					component.SetInt64(0)
				}
			}
		}
		value.Precomputed = rsa.PrecomputedValues{}
	case ed25519.PrivateKey:
		clear(value)
	}
}

func colonHex(value []byte) string {
	encoded := strings.ToUpper(hex.EncodeToString(value))
	var builder strings.Builder
	builder.Grow(len(encoded) + len(encoded)/2)
	for index := 0; index < len(encoded); index += 2 {
		if index != 0 {
			builder.WriteByte(':')
		}
		builder.WriteString(encoded[index : index+2])
	}
	return builder.String()
}
