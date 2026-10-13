//go:build !linux

package instanceaccess

import (
	"crypto"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type DNSOrderOperation func(crypto.Signer, string, string, []string, func(string) error) (acmeorder.Instructions, error)

func ReadStagingOrder(_ string, _, _ []byte, _ [32]byte) (inventorystore.OrderStatus, uint64, error) {
	return inventorystore.OrderStatus{}, 0, ErrRecoveryUnsupported
}
func RunStagingOrder(_ string, _, _ []byte, _ [32]byte, _ uint64, _ []string, _ bool, _ func() bool, _ DNSOrderOperation) (inventorystore.OrderStatus, uint64, error) {
	return inventorystore.OrderStatus{}, 0, ErrRecoveryUnsupported
}

func RunStagingRenewalOrder(_ string, _, _ []byte, _ [32]byte, _ uint64, _ string, _ func() bool, _ DNSOrderOperation) (inventorystore.OrderStatus, uint64, error) {
	return inventorystore.OrderStatus{}, 0, ErrRecoveryUnsupported
}
func AcknowledgeStagingDNS(_ string, _, _ []byte, _ [32]byte, _ uint64, _ func() bool) (inventorystore.OrderStatus, uint64, error) {
	return inventorystore.OrderStatus{}, 0, ErrRecoveryUnsupported
}
