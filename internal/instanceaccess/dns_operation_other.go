//go:build !linux

package instanceaccess

import "github.com/denyfirst/rootwell/internal/inventorystore"

func RunStagingDNS(string, []byte, []byte, [32]byte, uint64, int, string, func() bool, inventorystore.DNSOperation) (inventorystore.DNSPlanStatus, uint64, error) {
	return inventorystore.DNSPlanStatus{}, 0, ErrRecoveryUnsupported
}
