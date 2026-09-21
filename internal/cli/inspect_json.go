package cli

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/certinspect"
)

const inspectSchemaVersion = "rootwell.inspect.x509.v1"

var errInvalidJSONText = errors.New("certificate metadata contains invalid UTF-8")

type inspectJSON struct {
	SchemaVersion               string               `json:"schema_version"`
	ObjectType                  string               `json:"object_type"`
	Encoding                    string               `json:"encoding"`
	Subject                     string               `json:"subject"`
	Issuer                      string               `json:"issuer"`
	Serial                      string               `json:"serial"`
	Validity                    validityJSON         `json:"validity"`
	PublicKey                   publicKeyJSON        `json:"public_key"`
	SignatureAlgorithm          string               `json:"signature_algorithm"`
	BasicConstraints            basicConstraintsJSON `json:"basic_constraints"`
	KeyUsage                    []string             `json:"key_usage"`
	ExtendedKeyUsage            []string             `json:"extended_key_usage"`
	UnknownExtendedKeyUsage     []string             `json:"unknown_extended_key_usage"`
	SubjectKeyID                string               `json:"subject_key_id"`
	AuthorityKeyID              string               `json:"authority_key_id"`
	SubjectAlternativeNames     alternativeNamesJSON `json:"subject_alternative_names"`
	CriticalExtensions          []string             `json:"critical_extensions"`
	UnhandledCriticalExtensions []string             `json:"unhandled_critical_extensions"`
	Fingerprints                fingerprintsJSON     `json:"fingerprints"`
}

type validityJSON struct {
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

type publicKeyJSON struct {
	Algorithm string `json:"algorithm"`
	Bits      int    `json:"bits"`
	Curve     string `json:"curve"`
}

type basicConstraintsJSON struct {
	Present       bool `json:"present"`
	IsCA          bool `json:"is_ca"`
	MaxPathLength *int `json:"max_path_length"`
}

type alternativeNamesJSON struct {
	DNS   []string `json:"dns"`
	Email []string `json:"email"`
	IP    []string `json:"ip"`
	URI   []string `json:"uri"`
}

type fingerprintsJSON struct {
	SHA256 string `json:"sha256"`
}

func renderCertificateJSON(result certinspect.Result) (string, error) {
	document := inspectJSON{
		SchemaVersion:      inspectSchemaVersion,
		ObjectType:         "x509-certificate",
		Encoding:           string(result.Encoding),
		Subject:            result.Subject,
		Issuer:             result.Issuer,
		Serial:             result.Serial,
		Validity:           validityJSON{NotBefore: formatTime(result.NotBefore), NotAfter: formatTime(result.NotAfter)},
		PublicKey:          publicKeyJSON{Algorithm: result.PublicKeyAlgorithm, Bits: result.PublicKeyBits, Curve: result.PublicKeyCurve},
		SignatureAlgorithm: result.SignatureAlgorithm,
		BasicConstraints: basicConstraintsJSON{
			Present:       result.BasicConstraintsValid,
			IsCA:          result.IsCA,
			MaxPathLength: result.MaxPathLength,
		},
		KeyUsage:                    nonNil(result.KeyUsage),
		ExtendedKeyUsage:            nonNil(result.ExtendedKeyUsage),
		UnknownExtendedKeyUsage:     nonNil(result.UnknownExtendedKeyUsage),
		SubjectKeyID:                result.SubjectKeyID,
		AuthorityKeyID:              result.AuthorityKeyID,
		CriticalExtensions:          nonNil(result.CriticalExtensions),
		UnhandledCriticalExtensions: nonNil(result.UnhandledCriticalExtensions),
		SubjectAlternativeNames: alternativeNamesJSON{
			DNS:   nonNil(result.DNSNames),
			Email: nonNil(result.EmailAddresses),
			IP:    nonNil(result.IPAddresses),
			URI:   nonNil(result.URIs),
		},
		Fingerprints: fingerprintsJSON{SHA256: result.SHA256Fingerprint},
	}
	if !validJSONStrings(reflect.ValueOf(document)) {
		return "", errInvalidJSONText
	}

	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", err
	}
	return string(append(asciiJSON(encoded), '\n')), nil
}

func validJSONStrings(value reflect.Value) bool {
	if !value.IsValid() {
		return true
	}
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		return value.IsNil() || validJSONStrings(value.Elem())
	case reflect.String:
		return utf8.ValidString(value.String())
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if !validJSONStrings(value.Field(index)) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if !validJSONStrings(value.Index(index)) {
				return false
			}
		}
	}
	return true
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}

// asciiJSON preserves JSON string semantics while ensuring that requested
// output cannot place Unicode formatting controls directly on a terminal.
func asciiJSON(encoded []byte) []byte {
	output := make([]byte, 0, len(encoded))
	for len(encoded) > 0 {
		if encoded[0] < 0x7f {
			output = append(output, encoded[0])
			encoded = encoded[1:]
			continue
		}
		if encoded[0] == 0x7f {
			output = appendUnicodeEscape(output, 0x7f)
			encoded = encoded[1:]
			continue
		}

		value, size := utf8.DecodeRune(encoded)
		if value == utf8.RuneError && size == 1 {
			value = '\uFFFD'
		}
		encoded = encoded[size:]
		if value <= 0xFFFF {
			output = appendUnicodeEscape(output, value)
			continue
		}
		value -= 0x10000
		high := rune(0xD800) + value>>10
		low := rune(0xDC00) + (value & 0x3FF)
		output = appendUnicodeEscape(output, high)
		output = appendUnicodeEscape(output, low)
	}
	return output
}

func appendUnicodeEscape(destination []byte, value rune) []byte {
	const hexadecimal = "0123456789abcdef"
	return append(destination,
		'\\', 'u',
		hexadecimal[value>>12],
		hexadecimal[value>>8&0x0f],
		hexadecimal[value>>4&0x0f],
		hexadecimal[value&0x0f],
	)
}
