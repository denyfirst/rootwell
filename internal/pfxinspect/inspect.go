package pfxinspect

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/limits"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var (
	// ErrWrongPassword means the MAC did not verify with this password.
	ErrWrongPassword = errors.New("PFX password is wrong")
	// ErrInvalid means the PFX opened but does not hold exactly one RSA or EC
	// key and the one non-CA certificate it belongs to.
	ErrInvalid = errors.New("PFX could not be authenticated or contains unsupported material")
)

// The pinned decoder's strict lister names only these three bag attributes.
// Windows adds others (machine key set, extended properties) that Rootwell
// neither keeps nor needs.
const unknownAttributePrefix = "pkcs12: unknown attribute with OID "

const maxCertificates = 16

// Code names a refusal for the browser pages, which word it for a person.
func Code(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrWrongPassword):
		return "wrong-password"
	case errors.Is(err, ErrNotPFX):
		return "not-pfx"
	case errors.Is(err, ErrNoIntegrity):
		return "no-integrity"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	default:
		return "contents"
	}
}

// Result contains public metadata and private copies of public certificate DER.
// Additional certificates are in file order, not a verified issuer path;
// none becomes a trust anchor.
type Result struct {
	MatchingCertificate certinspect.Result
	Additional          []certinspect.Result
	publicDER           map[string][]byte
}

// CertificateDER returns a copy of the exact public certificate selected by
// the fingerprint shown by pfx-inspect. It never returns private-key material.
func (result Result) CertificateDER(fingerprint string) ([]byte, bool) {
	if !ValidFingerprint(fingerprint) {
		return nil, false
	}
	der, ok := result.publicDER[fingerprint]
	if !ok {
		return nil, false
	}
	return bytes.Clone(der), true
}

// ValidFingerprint accepts only the exact uppercase colon-hex SHA-256 form
// displayed by the inspection command.
func ValidFingerprint(value string) bool {
	if len(value) != 95 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if index%3 == 2 {
			if value[index] != ':' {
				return false
			}
		} else if !((value[index] >= '0' && value[index] <= '9') || (value[index] >= 'A' && value[index] <= 'F')) {
			return false
		}
	}
	return true
}

// Inspect opens the bounded profile with its password, which may be empty
// for a PFX saved without one. It rejects unknown bags and ambiguous
// key/certificate sets. No private-key bytes are returned or written.
func Inspect(input []byte, password string) (Result, error) {
	var result Result
	err := Open(input, password, func(opened Result, _ crypto.Signer) error {
		result = opened
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

// Open is Inspect that also lends the one matching key to use. The key is
// cleared on a best-effort basis when use returns; use must not keep it or
// put it in an error. Callers export it only after an explicit request.
func Open(input []byte, password string, use func(Result, crypto.Signer) error) error {
	if use == nil || !validPassword(password) {
		return ErrInvalid
	}
	if err := Preflight(input); err != nil {
		return err
	}
	key, certificates, err := decode(input, password)
	if err != nil {
		return err
	}
	defer keymatch.ClearParsedKey(key)
	result, err := match(key, certificates)
	if err != nil {
		return err
	}
	return use(result, key)
}

// decode authenticates the PFX and returns its one key and its certificates.
// ToPEM lists every bag and refuses unknown bag kinds; it is used only as
// that lister, and its mislabelled raw-key blocks are never published. When
// it stops at a bag attribute it cannot name, DecodeChain, which ignores
// attributes, reads the same authenticated contents instead.
func decode(input []byte, password string) (crypto.Signer, []*x509.Certificate, error) {
	//lint:ignore SA1019 We consume only typed bytes and never emit the deprecated PEM representation.
	blocks, err := pkcs12.ToPEM(input, password)
	defer func() {
		for _, block := range blocks {
			if block != nil {
				clear(block.Bytes)
			}
		}
	}()
	switch {
	case errors.Is(err, pkcs12.ErrIncorrectPassword):
		return nil, nil, ErrWrongPassword
	case err == nil:
		return fromBlocks(blocks)
	case strings.HasPrefix(err.Error(), unknownAttributePrefix):
		return fromChain(input, password)
	default:
		return nil, nil, ErrInvalid
	}
}

func fromBlocks(blocks []*pem.Block) (crypto.Signer, []*x509.Certificate, error) {
	if len(blocks) < 2 || len(blocks) > maxCertificates+1 {
		return nil, nil, ErrInvalid
	}
	var key crypto.Signer
	var certificates []*x509.Certificate
	fail := func() (crypto.Signer, []*x509.Certificate, error) {
		if key != nil {
			keymatch.ClearParsedKey(key)
		}
		return nil, nil, ErrInvalid
	}
	for _, block := range blocks {
		if block == nil {
			return fail()
		}
		switch block.Type {
		case "PRIVATE KEY":
			if key != nil || len(block.Bytes) == 0 || int64(len(block.Bytes)) > limits.MaxPrivateKeyBytes {
				return fail()
			}
			// Despite the label these are raw PKCS#1 or SEC 1 bytes.
			if parsed, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
				key = parsed
				break
			}
			parsed, parseErr := x509.ParseECPrivateKey(block.Bytes)
			if parseErr != nil {
				return fail()
			}
			key = parsed
		case "CERTIFICATE":
			// A parsed certificate aliases its input, and the blocks are
			// cleared when decode returns: parse a copy.
			certificate, _, parseErr := certinspect.Parse(bytes.Clone(block.Bytes))
			if parseErr != nil {
				return fail()
			}
			certificates = append(certificates, certificate)
		default:
			return fail()
		}
	}
	if key == nil {
		return fail()
	}
	return key, certificates, nil
}

func fromChain(input []byte, password string) (crypto.Signer, []*x509.Certificate, error) {
	parsed, leaf, others, err := pkcs12.DecodeChain(input, password)
	if err != nil {
		if parsed != nil {
			keymatch.ClearParsedKey(parsed)
		}
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, nil, ErrWrongPassword
		}
		return nil, nil, ErrInvalid
	}
	var key crypto.Signer
	switch value := parsed.(type) {
	case *rsa.PrivateKey:
		key = value
	case *ecdsa.PrivateKey:
		key = value
	default:
		keymatch.ClearParsedKey(parsed)
		return nil, nil, ErrInvalid
	}
	if leaf == nil {
		keymatch.ClearParsedKey(key)
		return nil, nil, ErrInvalid
	}
	return key, append([]*x509.Certificate{leaf}, others...), nil
}

// match requires exactly one non-CA certificate for the key, no duplicates
// and at most 16 certificates. The match is by public key, not bag order.
func match(key crypto.Signer, certificates []*x509.Certificate) (Result, error) {
	if len(certificates) == 0 || len(certificates) > maxCertificates {
		return Result{}, ErrInvalid
	}
	keySPKI, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return Result{}, ErrInvalid
	}
	result := Result{publicDER: make(map[string][]byte)}
	seen := make(map[[32]byte]bool)
	matches := 0
	for _, certificate := range certificates {
		digest := sha256.Sum256(certificate.Raw)
		if seen[digest] {
			return Result{}, ErrInvalid
		}
		seen[digest] = true
		report, inspectErr := certinspect.Inspect(certificate.Raw)
		if inspectErr != nil {
			return Result{}, ErrInvalid
		}
		result.publicDER[report.SHA256Fingerprint] = bytes.Clone(certificate.Raw)
		certificateSPKI, marshalErr := x509.MarshalPKIXPublicKey(certificate.PublicKey)
		if marshalErr != nil {
			return Result{}, ErrInvalid
		}
		if len(keySPKI) == len(certificateSPKI) && subtle.ConstantTimeCompare(keySPKI, certificateSPKI) == 1 {
			if certificate.IsCA {
				return Result{}, ErrInvalid
			}
			matches++
			result.MatchingCertificate = report
		} else {
			result.Additional = append(result.Additional, report)
		}
	}
	if matches != 1 || len(result.Additional)+1 != len(certificates) {
		return Result{}, ErrInvalid
	}
	return result, nil
}

// validPassword accepts an empty password, for a PFX saved without one, or
// up to 128 bytes of printable text. Control characters never reach the KDF.
func validPassword(value string) bool {
	if len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
