//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func TestProductionAccountUnsupportedPlatformCannotReadWriteOrCallPermit(t *testing.T) {
	status, gen, err := ReadProductionAccount("unused", nil, nil, [32]byte{})
	if !errors.Is(err, ErrRecoveryUnsupported) || status != (inventorystore.AccountStatus{}) || gen != 0 {
		t.Fatal("native read enabled")
	}
	status, gen, err = PrepareProductionAccount("unused", nil, nil, [32]byte{}, 1, func() bool { t.Fatal("native permission callback called"); return true })
	if !errors.Is(err, ErrRecoveryUnsupported) || status != (inventorystore.AccountStatus{}) || gen != 0 {
		t.Fatal("native write enabled")
	}
}
