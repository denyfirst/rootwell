//go:build !linux

package instanceaccess

import (
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"time"
)

func ReadTimingReadiness(string, []byte, []byte, [32]byte, uint64, string, time.Time) (inventorystore.TimingReadiness, error) {
	return inventorystore.TimingReadiness{}, ErrRecoveryUnsupported
}
