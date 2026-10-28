//go:build !linux

package instanceaccess

import (
	"errors"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"testing"
)

func TestHistoryArchiveNativeRefusesBeforePermit(t *testing.T) {
	called := false
	s, err := InventoryHistoryArchive("unreadable", nil, nil, [32]byte{}, 1, func() bool { called = true; return true })
	if !errors.Is(err, ErrRecoveryUnsupported) || called || s != (inventorystore.HistoryArchiveStatus{}) {
		t.Fatal("native archive reached storage/permit")
	}
}
