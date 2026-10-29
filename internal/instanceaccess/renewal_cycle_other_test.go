//go:build !linux

package instanceaccess

import (
	"errors"
	"reflect"
	"testing"

	"github.com/denyfirst/rootwell/internal/inventorystore"
)

func TestNativeRenewalCycleRefusesBeforeFiles(t *testing.T) {
	p, err := ReadRenewalCycle("missing-private-store", nil, nil, [32]byte{}, 13, "public-selection")
	if !errors.Is(err, ErrRecoveryUnsupported) || !reflect.DeepEqual(p, inventorystore.RenewalCycle{}) {
		t.Fatal("native gained custody or partial projection", err)
	}
}
