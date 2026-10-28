//go:build !linux

package instanceaccess

import "github.com/denyfirst/rootwell/internal/inventorystore"

func InventoryHistoryArchive(string, []byte, []byte, [32]byte, uint64, func() bool) (inventorystore.HistoryArchiveStatus, error) {
	return inventorystore.HistoryArchiveStatus{}, ErrRecoveryUnsupported
}
