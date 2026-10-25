//go:build !linux

package instanceaccess

import (
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"time"
)

func ReadAutomationStatus(_ string, _, _ []byte, _ [32]byte, _ time.Time) (inventorystore.AutomationStatus, error) {
	return inventorystore.AutomationStatus{}, ErrRecoveryUnsupported
}
