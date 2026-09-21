// Package certinspect parses one bounded X.509 certificate for metadata only.
// Successful parsing is not a trust, chain, signature, or policy verdict.
package certinspect

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
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
	Encoding           Encoding
	Subject            string
	Issuer             string
	Serial             string
	NotBefore          time.Time
	NotAfter           time.Time
	PublicKeyAlgorithm string
	SignatureAlgorithm string
	SHA256Fingerprint  string
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []string
	URIs               []string
	IsCA               bool
}

// Inspect parses exactly one PEM or DER X.509 certificate. It performs no
// network access and makes no trust or validity decision.
func Inspect(input []byte) (Result, error) {
	if len(input) == 0 {
		return Result{}, ErrEmpty
	}
	if int64(len(input)) > limits.MaxInputBytes {
		return Result{}, ErrTooLarge
	}

	der, encoding, err := decode(input)
	if err != nil {
		return Result{}, err
	}

	var object asn1.RawValue
	rest, err := asn1.Unmarshal(der, &object)
	if err != nil || object.Class != asn1.ClassUniversal || object.Tag != asn1.TagSequence || !object.IsCompound {
		return Result{}, ErrInvalidCertificate
	}
	if len(rest) != 0 {
		return Result{}, ErrTrailingData
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return Result{}, ErrInvalidCertificate
	}
	return resultFromCertificate(certificate, encoding)
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
	result := Result{
		Encoding:           encoding,
		Subject:            certificate.Subject.String(),
		Issuer:             certificate.Issuer.String(),
		NotBefore:          certificate.NotBefore,
		NotAfter:           certificate.NotAfter,
		PublicKeyAlgorithm: certificate.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: certificate.SignatureAlgorithm.String(),
		SHA256Fingerprint:  colonHex(digest[:]),
		IsCA:               certificate.IsCA,
	}
	valueCount := len(certificate.DNSNames) + len(certificate.EmailAddresses) + len(certificate.IPAddresses) + len(certificate.URIs)
	if valueCount > limits.MaxMetadataValues {
		return Result{}, ErrResourceLimit
	}
	textBytes := len(result.Subject) + len(result.Issuer)
	if textBytes > limits.MaxMetadataTextBytes {
		return Result{}, ErrResourceLimit
	}
	for _, value := range certificate.DNSNames {
		if !addMetadataSize(&textBytes, value) {
			return Result{}, ErrResourceLimit
		}
		result.DNSNames = append(result.DNSNames, value)
	}
	for _, value := range certificate.EmailAddresses {
		if !addMetadataSize(&textBytes, value) {
			return Result{}, ErrResourceLimit
		}
		result.EmailAddresses = append(result.EmailAddresses, value)
	}
	if certificate.SerialNumber != nil {
		result.Serial = strings.ToUpper(certificate.SerialNumber.Text(16))
	}
	for _, address := range certificate.IPAddresses {
		value := address.String()
		if !addMetadataSize(&textBytes, value) {
			return Result{}, ErrResourceLimit
		}
		result.IPAddresses = append(result.IPAddresses, value)
	}
	for _, identifier := range certificate.URIs {
		value := identifier.String()
		if !addMetadataSize(&textBytes, value) {
			return Result{}, ErrResourceLimit
		}
		result.URIs = append(result.URIs, value)
	}
	return result, nil
}

func addMetadataSize(total *int, value string) bool {
	if len(value) > limits.MaxMetadataTextBytes-*total {
		return false
	}
	*total += len(value)
	return true
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
