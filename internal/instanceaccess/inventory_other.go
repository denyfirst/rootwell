//go:build !linux

package instanceaccess

import (
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

func AppendCertificate(_ string, _, _ []byte, _ [32]byte, _ uint64, _, _, _ []byte, _, _, _ string) (publicinventory.Record, uint64, error) {
	return publicinventory.Record{}, 0, ErrRecoveryUnsupported
}
func AppendCertificateMaterial(_ string, _, _ []byte, _ [32]byte, _ uint64, _, _, _ []byte, _, _, _ string, _ bool) (publicinventory.Record, uint64, error) {
	return publicinventory.Record{}, 0, ErrRecoveryUnsupported
}
func CheckCertificateKey(_ string, _, _ []byte, _ [32]byte, _ uint64, _, _ []byte, _ string) (publicinventory.Record, error) {
	return publicinventory.Record{}, ErrRecoveryUnsupported
}
func AttachCertificateKey(_ string, _, _ []byte, _ [32]byte, _ uint64, _, _ []byte, _ string, _ bool) (publicinventory.Record, uint64, error) {
	return publicinventory.Record{}, 0, ErrRecoveryUnsupported
}
func WithCertificate(_ string, _, _ []byte, _ [32]byte, _ uint64, _ string, _ func(publicinventory.Record, []byte) error) error {
	return ErrRecoveryUnsupported
}

// Native non-Linux private-store semantics have not yet been reviewed.
func ReadInventoryHistory(_ string, _, _ []byte, _ [32]byte) ([]inventorystore.Event, uint64, error) {
	return nil, 0, ErrRecoveryUnsupported
}
func InitializeInventory(_, _, _, _ string) error { return ErrRecoveryUnsupported }
func ReadInventory(_ string, _, _ []byte, _ [32]byte) ([]publicinventory.Record, uint64, error) {
	return nil, 0, ErrRecoveryUnsupported
}
func AppendInventory(_ string, _, _ []byte, _ [32]byte, _ []byte, _, _ string) ([]publicinventory.Record, uint64, error) {
	return nil, 0, ErrRecoveryUnsupported
}
func AssociateInventoryLocation(_ string, _, _ []byte, _ [32]byte, _ uint64, _, _ string) (publicinventory.Record, uint64, error) {
	return publicinventory.Record{}, 0, ErrRecoveryUnsupported
}
func UpdateInventoryOwner(_ string, _, _ []byte, _ [32]byte, _ uint64, _, _ string) (publicinventory.Record, uint64, error) {
	return publicinventory.Record{}, 0, ErrRecoveryUnsupported
}
func ChangeInventoryLocation(_ string, _, _ []byte, _ [32]byte, _ uint64, _, _, _ string, _ inventorystore.LocationChange) (publicinventory.Record, uint64, error) {
	return publicinventory.Record{}, 0, ErrRecoveryUnsupported
}
func DeleteInventoryRecord(_ string, _, _ []byte, _ [32]byte, _ uint64, _ string) (uint64, error) {
	return 0, ErrRecoveryUnsupported
}
func ExportFullSnapshot(_, _, _, _ string) error { return ErrRecoveryUnsupported }
func VerifyFullSnapshot(_, _ string, _ SnapshotUnlock) ([]byte, uint64, error) {
	return nil, 0, ErrRecoveryUnsupported
}
func RestoreFullSnapshot(_, _, _ string, _ SnapshotUnlock) error { return ErrRecoveryUnsupported }
