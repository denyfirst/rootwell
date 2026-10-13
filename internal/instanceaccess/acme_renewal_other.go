//go:build !linux

package instanceaccess

import "github.com/denyfirst/rootwell/internal/inventorystore"

func ReadStagingRenewalSource(_ string, _, _ []byte, _ [32]byte, _ uint64, _ string) (inventorystore.RenewalSource, uint64, error) {
	return inventorystore.RenewalSource{}, 0, ErrRecoveryUnsupported
}
