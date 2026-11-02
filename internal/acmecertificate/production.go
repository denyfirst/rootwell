package acmecertificate

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/certverify"
)

var ErrProductionInvalid = errors.New("production certificate response could not be safely accepted")

// Two official self-signed production roots, reviewed 2026-10-29. These are
// exclusively for offline production receipt acceptance, not ambient OS trust.
// No staging root is included. Rotation requires reviewed code/asset changes.
//
//go:embed production-roots.pem
var productionRootPEM string

var productionRootPins = [...]string{
	"96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6",
	"69729B8E15A86EFC177A57AFB7171DFC64ADD28C2FCA8CF1507E34453CCB1470",
}

func productionTrust() ([]*x509.Certificate, error) { return checkedProductionRoots(productionRootPEM) }
func checkedProductionRoots(input string) ([]*x509.Certificate, error) {
	if len(input) == 0 || len(input) > maxRootBytes {
		return nil, ErrProductionInvalid
	}
	roots, err := certverify.ParseTrustAnchors([]byte(input))
	if err != nil || len(roots) != len(productionRootPins) {
		return nil, ErrProductionInvalid
	}
	for i, root := range roots {
		digest := sha256.Sum256(root.Raw)
		if strings.ToUpper(hex.EncodeToString(digest[:])) != productionRootPins[i] || !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 || !bytes.Equal(root.RawSubject, root.RawIssuer) || root.CheckSignatureFrom(root) != nil || certverify.CheckCertificatePolicy(root) != nil {
			return nil, ErrProductionInvalid
		}
	}
	return roots, nil
}

// CheckProduction has no network, system trust, configurable roots or issuance
// authority. All existing key/CSR/name/usage/chain/expiry constraints still apply.
// It must not be substituted for the staging custody's fixed Check entry point.
func CheckProduction(private, csr []byte, names []string, response [][]byte, at time.Time) (Result, error) {
	roots, err := productionTrust()
	if err != nil {
		return Result{}, ErrProductionInvalid
	}
	return productionReceipt(private, csr, names, response, at, roots)
}

// Private synthetic-path test seam. The only runtime caller above supplies
// fixed, independently pinned production roots; no caller may inject trust.
func productionReceipt(private, csr []byte, names []string, response [][]byte, at time.Time, roots []*x509.Certificate) (Result, error) {
	result, err := check(private, csr, names, response, at, roots)
	if err != nil {
		return Result{}, ErrProductionInvalid
	}
	result.TestOnly = false
	return result, nil
}
