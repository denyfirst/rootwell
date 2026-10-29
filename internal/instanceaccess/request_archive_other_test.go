//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func TestRequestArchiveNativeRefusesBeforePermit(t *testing.T) {
	called := false
	s, err := InventoryRequestArchive("unreadable", nil, nil, [32]byte{}, 1, func() bool { called = true; return true })
	if !errors.Is(err, ErrRecoveryUnsupported) || called || s != (inventorystore.RequestArchiveStatus{}) {
		t.Fatal("native request archive reached storage/permit")
	}
}
