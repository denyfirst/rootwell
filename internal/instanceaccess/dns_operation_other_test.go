//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"

	"github.com/denyfirst/rootwell/internal/dnsrecord"
)

func TestNativeDNSOperationRefusesBeforePermissionAndSecretBorrow(t *testing.T) {
	s, g, err := RunStagingDNS("must-not-open", nil, nil, [32]byte{}, 1, 0, "add", func() bool { t.Fatal("native borrowed permit"); return true }, func(func() bool, []byte, dnsrecord.Scope, dnsrecord.State, bool, bool, func(dnsrecord.State) error) (dnsrecord.State, error) {
		t.Fatal("native borrowed token")
		return dnsrecord.State{}, nil
	})
	if !errors.Is(err, ErrRecoveryUnsupported) || s.Prepared || g != 0 {
		t.Fatal("native DNS custody enabled")
	}
}
