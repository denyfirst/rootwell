//go:build !linux

package instanceaccess

import "github.com/denyfirst/rootwell/internal/inventorystore"

func ReadStagingOrderLifecycle(string, []byte, []byte, [32]byte) (inventorystore.OrderStatus, inventorystore.CertificateRequestStatus, inventorystore.IssuanceStatus, uint64, error) {
	return inventorystore.OrderStatus{}, inventorystore.CertificateRequestStatus{}, inventorystore.IssuanceStatus{}, 0, ErrRecoveryUnsupported
}

func ReadStagingOrderPreparation(_ string, _, _ []byte, _ [32]byte) (inventorystore.OrderStatus, inventorystore.CertificateRequestStatus, uint64, error) {
	return inventorystore.OrderStatus{}, inventorystore.CertificateRequestStatus{}, 0, ErrRecoveryUnsupported
}
func PrepareStagingCertificateRequest(_ string, _, _ []byte, _ [32]byte, _ uint64, _ func() bool) (inventorystore.CertificateRequestStatus, uint64, error) {
	return inventorystore.CertificateRequestStatus{}, 0, ErrRecoveryUnsupported
}
