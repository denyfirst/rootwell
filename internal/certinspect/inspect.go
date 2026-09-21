// Package certinspect parses one bounded X.509 certificate for metadata only.
// Successful parsing is not a trust, chain, signature, or policy verdict.
package certinspect

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/limits"
)

var (
	ErrEmpty              = errors.New("certificate input is empty")
	ErrTooLarge           = errors.New("certificate input exceeds size limit")
	ErrUnsupportedFormat  = errors.New("certificate encoding is unsupported")
	ErrInvalidCertificate = errors.New("certificate is invalid")
	ErrTrailingData       = errors.New("certificate contains trailing data")
	ErrResourceLimit      = errors.New("certificate metadata exceeds limit")
)

// Encoding identifies the container used by the parsed certificate.
type Encoding string

const (
	EncodingPEM Encoding = "pem"
	EncodingDER Encoding = "der"
)

// Result contains certificate metadata and no private-key bytes. String values
// still originate in an untrusted certificate and must be escaped by renderers.
type Result struct {
	Encoding                    Encoding
	Subject                     string
	Issuer                      string
	Serial                      string
	NotBefore                   time.Time
	NotAfter                    time.Time
	PublicKeyAlgorithm          string
	PublicKeyBits               int
	PublicKeyCurve              string
	SignatureAlgorithm          string
	SHA256Fingerprint           string
	SubjectKeyID                string
	AuthorityKeyID              string
	KeyUsage                    []string
	ExtendedKeyUsage            []string
	UnknownExtendedKeyUsage     []string
	CriticalExtensions          []string
	UnhandledCriticalExtensions []string
	DNSNames                    []string
	EmailAddresses              []string
	IPAddresses                 []string
	URIs                        []string
	BasicConstraintsValid       bool
	IsCA                        bool
	MaxPathLength               *int
}

// Inspect parses exactly one PEM or DER X.509 certificate. It performs no
// network access and makes no trust or validity decision.
func Inspect(input []byte) (Result, error) {
	certificate, encoding, err := Parse(input)
	if err != nil {
		return Result{}, err
	}
	return resultFromCertificate(certificate, encoding)
}

// Parse returns exactly one bounded PEM or DER X.509 certificate. Callers must
// apply an explicit trust and algorithm policy before treating it as verified.
func Parse(input []byte) (*x509.Certificate, Encoding, error) {
	if len(input) == 0 {
		return nil, "", ErrEmpty
	}
	if int64(len(input)) > limits.MaxInputBytes {
		return nil, "", ErrTooLarge
	}

	der, encoding, err := decode(input)
	if err != nil {
		return nil, "", err
	}

	var object asn1.RawValue
	rest, err := asn1.Unmarshal(der, &object)
	if err != nil || object.Class != asn1.ClassUniversal || object.Tag != asn1.TagSequence || !object.IsCompound {
		return nil, "", ErrInvalidCertificate
	}
	if len(rest) != 0 {
		return nil, "", ErrTrailingData
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", ErrInvalidCertificate
	}
	return certificate, encoding, nil
}

func decode(input []byte) ([]byte, Encoding, error) {
	trimmed := bytes.TrimSpace(input)
	if len(trimmed) == 0 {
		return nil, "", ErrEmpty
	}

	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, "", ErrUnsupportedFormat
		}
		block, rest := pem.Decode(trimmed)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, "", ErrInvalidCertificate
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, "", ErrTrailingData
		}
		return block.Bytes, EncodingPEM, nil
	}

	return input, EncodingDER, nil
}

func resultFromCertificate(certificate *x509.Certificate, encoding Encoding) (Result, error) {
	digest := sha256.Sum256(certificate.Raw)
	publicKeyBits, publicKeyCurve := publicKeyDetails(certificate.PublicKey)
	result := Result{
		Encoding:              encoding,
		Subject:               certificate.Subject.String(),
		Issuer:                certificate.Issuer.String(),
		NotBefore:             certificate.NotBefore,
		NotAfter:              certificate.NotAfter,
		PublicKeyAlgorithm:    certificate.PublicKeyAlgorithm.String(),
		PublicKeyBits:         publicKeyBits,
		PublicKeyCurve:        publicKeyCurve,
		SignatureAlgorithm:    certificate.SignatureAlgorithm.String(),
		SHA256Fingerprint:     colonHex(digest[:]),
		KeyUsage:              keyUsageNames(certificate.KeyUsage),
		BasicConstraintsValid: certificate.BasicConstraintsValid,
		IsCA:                  certificate.IsCA,
	}
	if certificate.BasicConstraintsValid && (certificate.MaxPathLen > 0 || certificate.MaxPathLenZero) {
		maxPathLength := certificate.MaxPathLen
		result.MaxPathLength = &maxPathLength
	}
	valueCount := len(certificate.DNSNames) + len(certificate.EmailAddresses) + len(certificate.IPAddresses) + len(certificate.URIs) +
		len(certificate.ExtKeyUsage) + len(certificate.UnknownExtKeyUsage) + len(certificate.Extensions) + len(certificate.UnhandledCriticalExtensions)
	if valueCount > limits.MaxMetadataValues {
		return Result{}, ErrResourceLimit
	}
	if certificate.SerialNumber != nil && len(certificate.SerialNumber.Bytes()) > limits.MaxMetadataTextBytes/2 {
		return Result{}, ErrResourceLimit
	}
	if len(certificate.SubjectKeyId) > limits.MaxMetadataTextBytes/3 || len(certificate.AuthorityKeyId) > limits.MaxMetadataTextBytes/3 {
		return Result{}, ErrResourceLimit
	}
	if certificate.SerialNumber != nil {
		result.Serial = strings.ToUpper(certificate.SerialNumber.Text(16))
	}
	result.SubjectKeyID = colonHex(certificate.SubjectKeyId)
	result.AuthorityKeyID = colonHex(certificate.AuthorityKeyId)
	textBytes := len(result.Subject) + len(result.Issuer) + len(result.Serial) + len(result.SubjectKeyID) + len(result.AuthorityKeyID) + len(result.PublicKeyCurve)
	if textBytes > limits.MaxMetadataTextBytes {
		return Result{}, ErrResourceLimit
	}
	for _, usage := range certificate.ExtKeyUsage {
		result.ExtendedKeyUsage = append(result.ExtendedKeyUsage, extendedKeyUsageName(usage))
	}
	for _, identifier := range certificate.UnknownExtKeyUsage {
		value := identifier.String()
		if !appendMetadata(&result.UnknownExtendedKeyUsage, &textBytes, value) {
			return Result{}, ErrResourceLimit
		}
	}
	for _, extension := range certificate.Extensions {
		if !extension.Critical {
			continue
		}
		value := extension.Id.String()
		if !appendMetadata(&result.CriticalExtensions, &textBytes, value) {
			return Result{}, ErrResourceLimit
		}
	}
	for _, identifier := range certificate.UnhandledCriticalExtensions {
		value := identifier.String()
		if !appendMetadata(&result.UnhandledCriticalExtensions, &textBytes, value) {
			return Result{}, ErrResourceLimit
		}
	}
	for _, value := range certificate.DNSNames {
		if !appendMetadata(&result.DNSNames, &textBytes, value) {
			return Result{}, ErrResourceLimit
		}
	}
	for _, value := range certificate.EmailAddresses {
		if !appendMetadata(&result.EmailAddresses, &textBytes, value) {
			return Result{}, ErrResourceLimit
		}
	}
	for _, address := range certificate.IPAddresses {
		value := address.String()
		if !appendMetadata(&result.IPAddresses, &textBytes, value) {
			return Result{}, ErrResourceLimit
		}
	}
	for _, identifier := range certificate.URIs {
		value := identifier.String()
		if !appendMetadata(&result.URIs, &textBytes, value) {
			return Result{}, ErrResourceLimit
		}
	}
	return result, nil
}

func appendMetadata(destination *[]string, total *int, value string) bool {
	if !addMetadataSize(total, value) {
		return false
	}
	*destination = append(*destination, value)
	return true
}

func addMetadataSize(total *int, value string) bool {
	if len(value) > limits.MaxMetadataTextBytes-*total {
		return false
	}
	*total += len(value)
	return true
}

func colonHex(value []byte) string {
	if len(value) == 0 {
		return ""
	}
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

func publicKeyDetails(publicKey any) (int, string) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil {
			return 0, ""
		}
		return key.N.BitLen(), ""
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil || key.Curve.Params() == nil {
			return 0, ""
		}
		return key.Curve.Params().BitSize, key.Curve.Params().Name
	case ed25519.PublicKey:
		return len(key) * 8, ""
	default:
		return 0, ""
	}
}

func keyUsageNames(usage x509.KeyUsage) []string {
	known := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digital-signature"},
		{x509.KeyUsageContentCommitment, "content-commitment"},
		{x509.KeyUsageKeyEncipherment, "key-encipherment"},
		{x509.KeyUsageDataEncipherment, "data-encipherment"},
		{x509.KeyUsageKeyAgreement, "key-agreement"},
		{x509.KeyUsageCertSign, "certificate-signing"},
		{x509.KeyUsageCRLSign, "crl-signing"},
		{x509.KeyUsageEncipherOnly, "encipher-only"},
		{x509.KeyUsageDecipherOnly, "decipher-only"},
	}
	var names []string
	remaining := usage
	for _, item := range known {
		if usage&item.bit != 0 {
			names = append(names, item.name)
			remaining &^= item.bit
		}
	}
	if remaining != 0 {
		names = append(names, fmt.Sprintf("unknown-0x%X", int64(remaining)))
	}
	return names
}

func extendedKeyUsageName(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "server-auth"
	case x509.ExtKeyUsageClientAuth:
		return "client-auth"
	case x509.ExtKeyUsageCodeSigning:
		return "code-signing"
	case x509.ExtKeyUsageEmailProtection:
		return "email-protection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "ipsec-end-system"
	case x509.ExtKeyUsageIPSECTunnel:
		return "ipsec-tunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "ipsec-user"
	case x509.ExtKeyUsageTimeStamping:
		return "time-stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "ocsp-signing"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "microsoft-server-gated-crypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "netscape-server-gated-crypto"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "microsoft-commercial-code-signing"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "microsoft-kernel-code-signing"
	default:
		return fmt.Sprintf("unknown-%d", usage)
	}
}
