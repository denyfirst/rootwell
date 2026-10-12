//go:build !linux

package instanceaccess

import (
	"crypto"
	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type CertificateOperation func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (acmestaging.CertificateObservation, error)

func RunStagingCertificate(string, []byte, []byte, [32]byte, uint64, bool, func() bool, CertificateOperation) (inventorystore.IssuanceStatus, uint64, error) {
	return inventorystore.IssuanceStatus{}, 0, ErrRecoveryUnsupported
}
