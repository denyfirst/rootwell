//go:build !linux

package instanceaccess

import "github.com/denyfirst/rootwell/internal/inventorystore"

func CompleteStagingIssuance(string, []byte, []byte, [32]byte, uint64, [][]byte, func() bool) (inventorystore.IssuanceStatus, uint64, error) {
	return inventorystore.IssuanceStatus{}, 0, ErrRecoveryUnsupported
}
