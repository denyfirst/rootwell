//go:build !linux

package instanceaccess

import "github.com/denyfirst/rootwell/internal/inventorystore"

func ReadStagingAccount(_ string, _, _ []byte, _ [32]byte) (inventorystore.AccountStatus, uint64, error) {
	return inventorystore.AccountStatus{}, 0, ErrRecoveryUnsupported
}
func PrepareStagingAccount(_ string, _, _ []byte, _ [32]byte, _ uint64, _ func() bool) (inventorystore.AccountStatus, uint64, error) {
	return inventorystore.AccountStatus{}, 0, ErrRecoveryUnsupported
}
