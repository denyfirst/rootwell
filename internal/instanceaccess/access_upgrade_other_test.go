//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"
)

func TestNonLinuxIdentityUpgradeFailsClosed(t *testing.T) {
	if err := CommitIdentityUpgrade("unused", "unused", IdentityUpgradeCandidate{}); !errors.Is(err, ErrUpgradeUnsupported) {
		t.Fatalf("identity upgrade did not refuse unsupported platform: %v", err)
	}
}
