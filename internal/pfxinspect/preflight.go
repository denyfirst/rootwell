// Package pfxinspect opens a bounded, password-authenticated PFX profile and
// returns public certificate metadata, or lends its one matching key to a
// caller for an explicit export.
package pfxinspect

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	// ErrUnsupported covers every PFX that Rootwell refuses before trying the
	// password: a protection, layout or size it does not read.
	ErrUnsupported = errors.New("PFX profile is unsupported or malformed")
	// ErrNotPFX is a file that is not a PFX at all.
	ErrNotPFX = fmt.Errorf("%w: the file is not a PFX", ErrUnsupported)
	// ErrNoIntegrity is a PFX without a MAC: nothing shows whether it was changed.
	ErrNoIntegrity = fmt.Errorf("%w: the PFX has no integrity check", ErrUnsupported)
)

const (
	maxInputBytes = 1 << 20
	// The largest visible work factor. OpenSSL writes 2048, Windows 2000, and
	// Java at most 100000 (Java 8) or 10000 (later releases).
	maxIterations = 250_000
	// One key and at most 16 certificates, as in Inspect.
	maxBags       = 17
	maxAttributes = 8
)

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHAAnd128BitRC2CBC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}
	oidPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}
	oidPBES2                         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA1                      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA256                    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA512                    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC                     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC                     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC                     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	oidShroudedKey = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509Cert    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
)

// These small DER descriptors mirror only the visible PFX envelope. They are
// a pre-decryption work-factor and layout gate, not a PKCS#12 decoder: the
// pinned SSLMate library still verifies the MAC and decrypts.
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

type pbeParams struct {
	Salt       []byte
	Iterations int
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

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
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

// IsPFX reports whether input has the outer shape of a PFX, whatever its
// protection. It decides how a page treats a file, never whether it opens.
func IsPFX(input []byte) bool {
	if len(input) == 0 || len(input) > maxInputBytes {
		return false
	}
	var envelope pfxEnvelope
	return unmarshalExact(input, &envelope) == nil && envelope.Version == 3 &&
		(envelope.AuthSafe.ContentType.Equal(oidData) || envelope.AuthSafe.ContentType.Equal(oidSignedData))
}

// Preflight accepts the password-protected PFX layouts that Windows, .NET,
// OpenSSL (default and -legacy) and Java keytool write: a MAC with SHA-1,
// SHA-256 or SHA-512; two safes, one of them an unencrypted safe holding the
// one shrouded key; legacy PKCS#12 3DES or RC2 or PBES2/PBKDF2 with AES-CBC.
// Every visible work factor is capped before the dependency decodes it. A
// safe encrypted as a whole is not visible here; Inspect enumerates it after
// the MAC is verified. Preflight does not authenticate the PFX.
func Preflight(input []byte) error {
	if len(input) == 0 {
		return ErrNotPFX
	}
	if len(input) > maxInputBytes {
		return ErrUnsupported
	}
	var envelope pfxEnvelope
	if unmarshalExact(input, &envelope) != nil || envelope.Version != 3 {
		return ErrNotPFX
	}
	if !envelope.AuthSafe.ContentType.Equal(oidData) {
		if envelope.AuthSafe.ContentType.Equal(oidSignedData) {
			return ErrUnsupported
		}
		return ErrNotPFX
	}
	if len(envelope.MacData.Mac.Algorithm.Algorithm) == 0 {
		return ErrNoIntegrity
	}
	if checkMAC(envelope.MacData) != nil {
		return ErrUnsupported
	}
	var authenticated []byte
	if unmarshalExact(envelope.AuthSafe.Content.Bytes, &authenticated) != nil {
		return ErrUnsupported
	}
	var contents []contentInfo
	if unmarshalExact(authenticated, &contents) != nil || len(contents) != 2 {
		return ErrUnsupported
	}
	keys, plainSafes := 0, 0
	for _, content := range contents {
		switch {
		case content.ContentType.Equal(oidData):
			var safe []byte
			if unmarshalExact(content.Content.Bytes, &safe) != nil {
				return ErrUnsupported
			}
			found, err := checkVisibleBags(safe)
			if err != nil {
				return err
			}
			keys += found
			plainSafes++
		case content.ContentType.Equal(oidEncryptedData):
			var encrypted encryptedData
			if unmarshalExact(content.Content.Bytes, &encrypted) != nil || encrypted.Version != 0 || !encrypted.Content.ContentType.Equal(oidData) {
				return ErrUnsupported
			}
			if checkCiphertext(encrypted.Content.Algorithm, encrypted.Content.Bytes) != nil {
				return ErrUnsupported
			}
		default:
			return ErrUnsupported
		}
	}
	// The one key must sit in an unencrypted safe, where its own work factor
	// is visible and capped above. Two encrypted safes would hide it.
	if plainSafes == 0 || keys != 1 {
		return ErrUnsupported
	}
	return nil
}

func boundedIterations(value int) bool { return value >= 1 && value <= maxIterations }

func boundedSalt(salt []byte) bool { return len(salt) >= 8 && len(salt) <= 64 }

// absentOrNull accepts an AlgorithmIdentifier's parameters only when they are
// missing or an explicit NULL, the two encodings producers use.
func absentOrNull(parameters asn1.RawValue) bool {
	return len(parameters.FullBytes) == 0 || (len(parameters.FullBytes) == 2 && parameters.FullBytes[0] == 0x05 && parameters.FullBytes[1] == 0x00)
}

func checkMAC(mac macData) error {
	digest := 0
	switch algorithm := mac.Mac.Algorithm.Algorithm; {
	case algorithm.Equal(oidSHA1):
		digest = 20
	case algorithm.Equal(oidSHA256):
		digest = 32
	case algorithm.Equal(oidSHA512):
		digest = 64
	default:
		// SHA-384, SHA-224 and PBMAC1 are not read by the pinned decoder.
		return ErrUnsupported
	}
	if !absentOrNull(mac.Mac.Algorithm.Parameters) || len(mac.Mac.Digest) != digest || !boundedSalt(mac.MacSalt) || !boundedIterations(mac.Iterations) {
		return ErrUnsupported
	}
	return nil
}

// checkVisibleBags reads one unencrypted safe. Only certificate bags and
// shrouded key bags are allowed; it returns how many keys it holds.
func checkVisibleBags(safe []byte) (int, error) {
	var bags []safeBag
	if unmarshalExact(safe, &bags) != nil || len(bags) == 0 || len(bags) > maxBags {
		return 0, ErrUnsupported
	}
	keys := 0
	for _, bag := range bags {
		if len(bag.Attributes) > maxAttributes {
			return 0, ErrUnsupported
		}
		switch {
		case bag.ID.Equal(oidCertBag):
			var certificate certBag
			if unmarshalExact(bag.Value.Bytes, &certificate) != nil || !certificate.ID.Equal(oidX509Cert) || len(certificate.Data) == 0 {
				return 0, ErrUnsupported
			}
		case bag.ID.Equal(oidShroudedKey):
			var key encryptedPrivateKeyInfo
			if unmarshalExact(bag.Value.Bytes, &key) != nil || checkCiphertext(key.Algorithm, key.Bytes) != nil {
				return 0, ErrUnsupported
			}
			keys++
		default:
			// Plain key bags, CRL, secret and nested safe bags are refused.
			return 0, ErrUnsupported
		}
	}
	return keys, nil
}

// checkCiphertext caps one password-based encryption and checks that the
// ciphertext fills whole cipher blocks.
func checkCiphertext(algorithm pkix.AlgorithmIdentifier, ciphertext []byte) error {
	block, err := checkCipher(algorithm)
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > maxInputBytes || len(ciphertext)%block != 0 {
		return ErrUnsupported
	}
	return nil
}

func checkCipher(algorithm pkix.AlgorithmIdentifier) (int, error) {
	switch {
	case algorithm.Algorithm.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC),
		algorithm.Algorithm.Equal(oidPBEWithSHAAnd128BitRC2CBC),
		algorithm.Algorithm.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		var params pbeParams
		if unmarshalExact(algorithm.Parameters.FullBytes, &params) != nil || !boundedSalt(params.Salt) || !boundedIterations(params.Iterations) {
			return 0, ErrUnsupported
		}
		return 8, nil
	case algorithm.Algorithm.Equal(oidPBES2):
		return 16, checkPBES2(algorithm)
	default:
		return 0, ErrUnsupported
	}
}

func checkPBES2(algorithm pkix.AlgorithmIdentifier) error {
	var params pbes2Params
	if unmarshalExact(algorithm.Parameters.FullBytes, &params) != nil || !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return ErrUnsupported
	}
	keyLength := 0
	switch {
	case params.Cipher.Algorithm.Equal(oidAES128CBC):
		keyLength = 16
	case params.Cipher.Algorithm.Equal(oidAES192CBC):
		keyLength = 24
	case params.Cipher.Algorithm.Equal(oidAES256CBC):
		keyLength = 32
	default:
		return ErrUnsupported
	}
	var kdf pbkdf2Params
	if unmarshalExact(params.KDF.Parameters.FullBytes, &kdf) != nil || kdf.Salt.Class != asn1.ClassUniversal || kdf.Salt.Tag != asn1.TagOctetString ||
		kdf.Salt.IsCompound || !boundedSalt(kdf.Salt.Bytes) || !boundedIterations(kdf.Iterations) || (kdf.KeyLength != 0 && kdf.KeyLength != keyLength) {
		return ErrUnsupported
	}
	// An absent PRF means HMAC-SHA-1. SHA-224 and SHA-384 are not read by
	// the pinned decoder.
	if len(kdf.PRF.Algorithm) != 0 {
		if !kdf.PRF.Algorithm.Equal(oidHMACSHA1) && !kdf.PRF.Algorithm.Equal(oidHMACSHA256) && !kdf.PRF.Algorithm.Equal(oidHMACSHA512) {
			return ErrUnsupported
		}
		if !absentOrNull(kdf.PRF.Parameters) {
			return ErrUnsupported
		}
	}
	var iv []byte
	if unmarshalExact(params.Cipher.Parameters.FullBytes, &iv) != nil || len(iv) != 16 {
		return ErrUnsupported
	}
	return nil
}
