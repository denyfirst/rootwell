//go:build !linux

package instanceaccess

import (
	"crypto"
	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type DNSValidationOperation func(crypto.Signer, string, acmeorder.Instructions, []string, bool) (acmeorder.Validation, error)

func RunStagingValidation(_ string, _, _ []byte, _ [32]byte, _ uint64, _ bool, _ func() bool, _ DNSValidationOperation) (inventorystore.OrderStatus, uint64, error) {
	return inventorystore.OrderStatus{}, 0, ErrRecoveryUnsupported
}
