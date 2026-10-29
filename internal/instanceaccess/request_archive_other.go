//go:build !linux

package instanceaccess

import "github.com/denyfirst/rootwell/internal/inventorystore"

func InventoryRequestArchive(string, []byte, []byte, [32]byte, uint64, func() bool) (inventorystore.RequestArchiveStatus, error) {
	return inventorystore.RequestArchiveStatus{}, ErrRecoveryUnsupported
}
