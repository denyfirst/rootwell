//go:build !linux

package instanceaccess

import (
	"crypto"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type IssuanceOperation func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (string, error)

func ReadStagingIssuance(string, []byte, []byte, [32]byte) (inventorystore.IssuanceStatus, uint64, error) {
	return inventorystore.IssuanceStatus{}, 0, ErrRecoveryUnsupported
}

func RunStagingIssuance(string, []byte, []byte, [32]byte, uint64, bool, func() bool, IssuanceOperation) (inventorystore.IssuanceStatus, uint64, error) {
	return inventorystore.IssuanceStatus{}, 0, ErrRecoveryUnsupported
}
