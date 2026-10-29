//go:build !linux

package instanceaccess

import "github.com/denyfirst/rootwell/internal/inventorystore"

func ReadRenewalCycle(string, []byte, []byte, [32]byte, uint64, string) (inventorystore.RenewalCycle, error) {
	return inventorystore.RenewalCycle{}, ErrRecoveryUnsupported
}
