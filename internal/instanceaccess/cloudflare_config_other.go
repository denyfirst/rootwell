//go:build !linux

package instanceaccess

import "github.com/denyfirst/rootwell/internal/inventorystore"

func ReadCloudflareConfig(_ string, _, _ []byte, _ [32]byte) (inventorystore.CloudflareStatus, uint64, error) {
	return inventorystore.CloudflareStatus{}, 0, ErrRecoveryUnsupported
}
func ChangeCloudflareConfig(_ string, _, _ []byte, _ [32]byte, _ uint64, _, _ string, _ []byte, _ bool, _ func() bool) (inventorystore.CloudflareStatus, uint64, error) {
	return inventorystore.CloudflareStatus{}, 0, ErrRecoveryUnsupported
}
