//go:build !linux

package instanceaccess

import "github.com/denyfirst/rootwell/internal/inventorystore"

func ReadNewStagingRequest(string, []byte, []byte, [32]byte) (inventorystore.NewRequestStatus, uint64, error) {
	return inventorystore.NewRequestStatus{}, 0, ErrRecoveryUnsupported
}
func CloseStagingRequest(string, []byte, []byte, [32]byte, uint64, func() bool) (inventorystore.NewRequestStatus, uint64, error) {
	return inventorystore.NewRequestStatus{}, 0, ErrRecoveryUnsupported
}
