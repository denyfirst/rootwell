//go:build !linux

package instanceaccess

import "github.com/denyfirst/rootwell/internal/inventorystore"

func ReadStagingRenewalTiming(string, []byte, []byte, [32]byte, uint64, string) (inventorystore.RenewalTimingStatus, uint64, error) {
	return inventorystore.RenewalTimingStatus{}, 0, ErrRecoveryUnsupported
}
func RunStagingRenewalTiming(string, []byte, []byte, [32]byte, uint64, string, func() bool, inventorystore.RenewalTimingOperation) (inventorystore.RenewalTimingStatus, uint64, error) {
	return inventorystore.RenewalTimingStatus{}, 0, ErrRecoveryUnsupported
}
func InterruptStagingRenewalTiming(string, []byte, []byte, [32]byte, uint64, string, func() bool) (inventorystore.RenewalTimingStatus, uint64, error) {
	return inventorystore.RenewalTimingStatus{}, 0, ErrRecoveryUnsupported
}
