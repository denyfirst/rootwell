//go:build !linux

package instanceaccess

import (
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/providerretry"
)

func ReadStagingDNSPlan(_ string, _, _ []byte, _ [32]byte) (inventorystore.DNSPlanStatus, uint64, error) {
	return inventorystore.DNSPlanStatus{}, 0, ErrRecoveryUnsupported
}
func PrepareStagingDNSPlan(_ string, _, _ []byte, _ [32]byte, _ uint64, _ func() bool) (inventorystore.DNSPlanStatus, uint64, error) {
	return inventorystore.DNSPlanStatus{}, 0, ErrRecoveryUnsupported
}
func BeginStagingDNSAttempt(_ string, _, _ []byte, _ [32]byte, _ uint64, _ int, _ func() bool) (*inventorystore.DNSAttempt, inventorystore.DNSPlanStatus, uint64, error) {
	return nil, inventorystore.DNSPlanStatus{}, 0, ErrRecoveryUnsupported
}
func DeferStagingDNSAttempt(_ string, _, _ []byte, _ [32]byte, _ *inventorystore.DNSAttempt, _ providerretry.Hint, _ func() bool) (inventorystore.DNSPlanStatus, uint64, error) {
	return inventorystore.DNSPlanStatus{}, 0, ErrRecoveryUnsupported
}
