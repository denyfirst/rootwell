package acmecertificate

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"strings"

	"github.com/denyfirst/rootwell/internal/certverify"
)

// Four official self-signed staging roots, reviewed 2026-10-12. Test-only:
// NEVER install in ordinary system/browser trust. See roots.md for provenance.
//
//go:embed staging-roots.pem
var stagingRootPEM string

var stagingRootPins = [...]string{
	"E70570A989F8565AABDF7CAE27ABD1621872D6A3F811E3FEF27E3DBA02912198",
	"9B2A339FE6A3E85585C4CD75536CB8C1CF7CD603B9A64BEC2521858AE48DA85D",
	"B59BFC0BA52DAF849853B7324A91E82F031DB3397F35644157352CDE6384B56C",
	"EF115FB59E040FF39D15FD8F3EF54063C704321D83CB081213272F77D3091672",
}

func stagingTrust() ([]*x509.Certificate, error) {
	return checkedStagingRoots(stagingRootPEM)
}

// Asset-validation seam, not configurable/exported trust. The caller above
// always supplies the embedded asset; arbitrary roots still fail exact pins.
func checkedStagingRoots(input string) ([]*x509.Certificate, error) {
	if len(input) == 0 || len(input) > maxRootBytes {
		return nil, ErrInvalid
	}
	roots, err := certverify.ParseTrustAnchors([]byte(input))
	if err != nil || len(roots) != len(stagingRootPins) {
		return nil, ErrInvalid
	}
	for i, root := range roots {
		digest := sha256.Sum256(root.Raw)
		if strings.ToUpper(hex.EncodeToString(digest[:])) != stagingRootPins[i] || certverify.CheckCertificatePolicy(root) != nil {
			return nil, ErrInvalid
		}
	}
	return roots, nil
}
