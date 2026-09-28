// Package pfxinspect opens a deliberately narrow, password-authenticated PFX
// profile and returns public certificate metadata only.
package pfxinspect

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

var ErrUnsupported = errors.New("PFX profile is unsupported or malformed")

const (
	maxInputBytes = 1 << 20
	maxIterations = 250_000
)

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidPBES2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA256    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidShroudedKey   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
)

// These small DER descriptors mirror only the documented Modern2023 envelope.
// They are a pre-decryption work-factor gate, not a replacement PKCS#12 parser.
type pfxEnvelope struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type encryptedData struct {
	Version int
	Content struct {
		ContentType asn1.ObjectIdentifier
		Algorithm   pkix.AlgorithmIdentifier
		Bytes       []byte `asn1:"tag:0,optional"`
	}
}

type pbes2Params struct {
	KDF    pkix.AlgorithmIdentifier
	Cipher pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt       asn1.RawValue
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue  `asn1:"tag:0,explicit"`
	Attributes []bagAttribute `asn1:"set,optional"`
}

type bagAttribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type encryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Bytes     []byte
}

func unmarshalExact(input []byte, value any) error {
	rest, err := asn1.Unmarshal(input, value)
	if err != nil || len(rest) != 0 {
		return ErrUnsupported
	}
	return nil
}

// Preflight requires the exact two-safe-content modern profile and caps all
// three password KDFs before the dependency performs any expensive work. It
// does not authenticate the PFX; Inspect repeats the check and verifies MAC.
func Preflight(input []byte) error {
	if len(input) == 0 || len(input) > maxInputBytes {
		return ErrUnsupported
	}
	var envelope pfxEnvelope
	if unmarshalExact(input, &envelope) != nil || envelope.Version != 3 || !envelope.AuthSafe.ContentType.Equal(oidData) || !envelope.MacData.Mac.Algorithm.Algorithm.Equal(oidSHA256) || !boundedIterations(envelope.MacData.Iterations) || len(envelope.MacData.MacSalt) < 8 || len(envelope.MacData.MacSalt) > 64 || len(envelope.MacData.Mac.Digest) != 32 {
		return ErrUnsupported
	}
	var authenticated []byte
	if unmarshalExact(envelope.AuthSafe.Content.Bytes, &authenticated) != nil {
		return ErrUnsupported
	}
	var contents []contentInfo
	if unmarshalExact(authenticated, &contents) != nil || len(contents) != 2 || !contents[0].ContentType.Equal(oidEncryptedData) || !contents[1].ContentType.Equal(oidData) {
		return ErrUnsupported
	}
	var encrypted encryptedData
	if unmarshalExact(contents[0].Content.Bytes, &encrypted) != nil || encrypted.Version != 0 || !encrypted.Content.ContentType.Equal(oidData) || len(encrypted.Content.Bytes) == 0 || checkPBES2(encrypted.Content.Algorithm) != nil {
		return ErrUnsupported
	}
	var keySafe []byte
	if unmarshalExact(contents[1].Content.Bytes, &keySafe) != nil {
		return ErrUnsupported
	}
	var bags []safeBag
	if unmarshalExact(keySafe, &bags) != nil || len(bags) != 1 || !bags[0].ID.Equal(oidShroudedKey) {
		return ErrUnsupported
	}
	var keyInfo encryptedPrivateKeyInfo
	if unmarshalExact(bags[0].Value.Bytes, &keyInfo) != nil || len(keyInfo.Bytes) == 0 || checkPBES2(keyInfo.Algorithm) != nil {
		return ErrUnsupported
	}
	return nil
}

func boundedIterations(value int) bool { return value >= 1 && value <= maxIterations }

func checkPBES2(algorithm pkix.AlgorithmIdentifier) error {
	if !algorithm.Algorithm.Equal(oidPBES2) {
		return ErrUnsupported
	}
	var params pbes2Params
	if unmarshalExact(algorithm.Parameters.FullBytes, &params) != nil || !params.KDF.Algorithm.Equal(oidPBKDF2) || !params.Cipher.Algorithm.Equal(oidAES256CBC) {
		return ErrUnsupported
	}
	var kdf pbkdf2Params
	if unmarshalExact(params.KDF.Parameters.FullBytes, &kdf) != nil || kdf.Salt.Class != asn1.ClassUniversal || kdf.Salt.Tag != asn1.TagOctetString || len(kdf.Salt.Bytes) < 8 || len(kdf.Salt.Bytes) > 64 || !boundedIterations(kdf.Iterations) || (kdf.KeyLength != 0 && kdf.KeyLength != 32) || !kdf.PRF.Algorithm.Equal(oidHMACSHA256) {
		return ErrUnsupported
	}
	var iv []byte
	if unmarshalExact(params.Cipher.Parameters.FullBytes, &iv) != nil || len(iv) != 16 {
		return ErrUnsupported
	}
	return nil
}
