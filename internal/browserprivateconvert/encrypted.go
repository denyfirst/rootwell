package browserprivateconvert

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/limits"
	"github.com/youmark/pkcs8"
)

var (
	oidPBES2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidSHA256    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// encryptedDER accepts one bounded PBES2/PBKDF2-SHA256/AES-256-CBC
// EncryptedPrivateKeyInfo. The preflight runs before the third-party parser,
// which otherwise accepts attacker-controlled KDF work without a cap.
func encryptedDER(input []byte) ([]byte, keymatch.Encoding, bool, error) {
	if len(input) == 0 || int64(len(input)) > limits.MaxPrivateKeyBytes {
		return nil, "", false, ErrInvalid
	}
	trimmed := bytes.TrimSpace(input)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		block, rest := pem.Decode(trimmed)
		if block == nil {
			return nil, "", false, ErrInvalid
		}
		if block.Type != "ENCRYPTED PRIVATE KEY" {
			clear(block.Bytes)
			return nil, "", false, nil
		}
		if len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			clear(block.Bytes)
			return nil, "", false, ErrInvalid
		}
		if !validEncryptedProfile(block.Bytes) {
			clear(block.Bytes)
			return nil, "", false, ErrInvalid
		}
		return block.Bytes, keymatch.Encoding("encrypted-pkcs8-pem"), true, nil
	}
	if !validEncryptedProfile(input) {
		return nil, "", false, nil
	}
	return input, keymatch.Encoding("encrypted-pkcs8-der"), true, nil
}

func sequenceFields(input []byte, count int) ([][]byte, bool) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(input, &outer)
	if err != nil || len(rest) != 0 || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return nil, false
	}
	fields := make([][]byte, 0, count)
	for content := outer.Bytes; len(content) != 0; {
		if len(fields) == count {
			return nil, false
		}
		var field asn1.RawValue
		content, err = asn1.Unmarshal(content, &field)
		if err != nil {
			return nil, false
		}
		fields = append(fields, field.FullBytes)
	}
	return fields, len(fields) == count
}

func algorithm(input []byte) (pkix.AlgorithmIdentifier, bool) {
	var result pkix.AlgorithmIdentifier
	fields, ok := sequenceFields(input, 2)
	if !ok {
		return result, false
	}
	rest, err := asn1.Unmarshal(input, &result)
	return result, err == nil && len(rest) == 0 && len(fields) == 2
}

func validEncryptedProfile(input []byte) bool {
	outer, ok := sequenceFields(input, 2)
	if !ok {
		return false
	}
	encAlg, ok := algorithm(outer[0])
	if !ok || !encAlg.Algorithm.Equal(oidPBES2) {
		return false
	}
	var ciphertext []byte
	rest, err := asn1.Unmarshal(outer[1], &ciphertext)
	if err != nil || len(rest) != 0 || len(ciphertext) < 16 || len(ciphertext) > int(limits.MaxPrivateKeyBytes) || len(ciphertext)%16 != 0 {
		return false
	}
	params, ok := sequenceFields(encAlg.Parameters.FullBytes, 2)
	if !ok {
		return false
	}
	kdf, ok := algorithm(params[0])
	if !ok || !kdf.Algorithm.Equal(oidPBKDF2) {
		return false
	}
	kdfParams, ok := sequenceFields(kdf.Parameters.FullBytes, 3)
	if !ok {
		return false
	}
	var salt []byte
	rest, err = asn1.Unmarshal(kdfParams[0], &salt)
	if err != nil || len(rest) != 0 || len(salt) < 8 || len(salt) > 32 {
		return false
	}
	var iterations int
	rest, err = asn1.Unmarshal(kdfParams[1], &iterations)
	if err != nil || len(rest) != 0 || iterations < 1 || iterations > 1_000_000 {
		return false
	}
	prf, ok := algorithm(kdfParams[2])
	if !ok || !prf.Algorithm.Equal(oidSHA256) || !bytes.Equal(prf.Parameters.FullBytes, []byte{0x05, 0x00}) {
		return false
	}
	cipher, ok := algorithm(params[1])
	if !ok || !cipher.Algorithm.Equal(oidAES256CBC) {
		return false
	}
	var iv []byte
	rest, err = asn1.Unmarshal(cipher.Parameters.FullBytes, &iv)
	return err == nil && len(rest) == 0 && len(iv) == 16
}

func withInputKey(input, password []byte, use func(any, keymatch.Encoding) error) error {
	der, encoding, encrypted, err := encryptedDER(input)
	if err != nil {
		return ErrInvalid
	}
	if !encrypted {
		if len(password) != 0 {
			return ErrInvalid
		}
		return keymatch.WithPrivateKey(input, use)
	}
	if der != nil && &der[0] != &input[0] {
		defer clear(der)
	}
	if len(password) == 0 {
		return ErrInputPasswordRequired
	}
	if len(password) > 256 {
		return ErrInvalid
	}
	key, err := pkcs8.ParsePKCS8PrivateKey(der, password)
	if err != nil {
		return ErrInvalid
	}
	defer keymatch.ClearParsedKey(key)
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil || len(plain) > int(limits.MaxPrivateKeyBytes) {
		clear(plain)
		return ErrInvalid
	}
	defer clear(plain)
	return keymatch.WithPrivateKey(plain, func(validated any, _ keymatch.Encoding) error { return use(validated, encoding) })
}

// WithInputKey lends one strictly validated private key to an internal
// operation. Encrypted input is limited to the bounded profile above. The
// callback must neither retain the key nor expose it in errors or output.
func WithInputKey(input, password []byte, use func(any, keymatch.Encoding) error) error {
	if use == nil {
		return ErrInvalid
	}
	return withInputKey(input, password, use)
}
