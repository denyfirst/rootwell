//go:build !linux

package instanceaccess

import (
	"crypto"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func RunStagingRegistration(_ string, _, _ []byte, _ [32]byte, _ uint64, _ string, _ bool, _ func() bool, _ func(crypto.Signer, string) (string, bool, error)) (inventorystore.AccountStatus, uint64, error) {
	return inventorystore.AccountStatus{}, 0, ErrRecoveryUnsupported
}
