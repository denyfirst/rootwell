package pfxinspect

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/limits"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var ErrInvalid = errors.New("PFX could not be authenticated or contains unsupported material")

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

// Inspect accepts only the bounded modern profile and a nonempty printable
// ASCII password. It rejects unknown bags and ambiguous key/certificate sets.
// No private-key bytes are returned or written.
func Inspect(input []byte, password string) (Result, error) {
	if !validPassword(password) || Preflight(input) != nil {
		return Result{}, ErrUnsupported
	}
	// ToPEM is used only as a strict bag enumerator. Its PRIVATE KEY block is
	// actually raw RSA/EC DER despite the label; never publish these blocks.
	//lint:ignore SA1019 We consume only typed bytes and never emit the deprecated PEM representation.
	blocks, err := pkcs12.ToPEM(input, password)
	if err != nil {
		return Result{}, ErrInvalid
	}
	defer func() {
		for _, block := range blocks {
			if block != nil {
				clear(block.Bytes)
			}
		}
	}()
	if len(blocks) < 2 || len(blocks) > 17 {
		return Result{}, ErrInvalid
	}
	var key crypto.Signer
	var certificates []*x509.Certificate
	var reports []certinspect.Result
	publicDER := make(map[string][]byte)
	seen := make(map[[32]byte]bool)
	for _, block := range blocks {
		if block == nil {
			return Result{}, ErrInvalid
		}
		switch block.Type {
		case "PRIVATE KEY":
			if key != nil {
				return Result{}, ErrInvalid
			}
			if len(block.Bytes) == 0 || int64(len(block.Bytes)) > limits.MaxPrivateKeyBytes {
				return Result{}, ErrInvalid
			}
			parsed, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
			if parseErr == nil {
				key = parsed
				defer keymatch.ClearParsedKey(parsed)
				break
			}
			parsedEC, parseErr := x509.ParseECPrivateKey(block.Bytes)
			if parseErr != nil {
				return Result{}, ErrInvalid
			}
			key = parsedEC
			defer keymatch.ClearParsedKey(parsedEC)
		case "CERTIFICATE":
			if len(certificates) == 16 {
				return Result{}, ErrInvalid
			}
			certificate, _, parseErr := certinspect.Parse(block.Bytes)
			if parseErr != nil {
				return Result{}, ErrInvalid
			}
			digest := sha256.Sum256(certificate.Raw)
			if seen[digest] {
				return Result{}, ErrInvalid
			}
			seen[digest] = true
			report, inspectErr := certinspect.Inspect(block.Bytes)
			if inspectErr != nil {
				return Result{}, ErrInvalid
			}
			certificates = append(certificates, certificate)
			reports = append(reports, report)
			publicDER[report.SHA256Fingerprint] = bytes.Clone(certificate.Raw)
		default:
			return Result{}, ErrInvalid
		}
	}
	if key == nil || len(certificates) == 0 {
		return Result{}, ErrInvalid
	}
	keySPKI, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return Result{}, ErrInvalid
	}
	result := Result{publicDER: publicDER}
	matches := 0
	for index, certificate := range certificates {
		certificateSPKI, marshalErr := x509.MarshalPKIXPublicKey(certificate.PublicKey)
		if marshalErr != nil {
			return Result{}, ErrInvalid
		}
		if len(keySPKI) == len(certificateSPKI) && subtle.ConstantTimeCompare(keySPKI, certificateSPKI) == 1 {
			if certificate.IsCA {
				return Result{}, ErrInvalid
			}
			matches++
			result.MatchingCertificate = reports[index]
		} else {
			result.Additional = append(result.Additional, reports[index])
		}
	}
	if matches != 1 || len(result.Additional)+1 != len(certificates) {
		return Result{}, ErrInvalid
	}
	return result, nil
}

func validPassword(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}
