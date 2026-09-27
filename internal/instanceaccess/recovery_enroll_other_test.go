//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"
)

func TestNonLinuxRecoveryCeremonyFailsClosed(t *testing.T) {
	path, password, _, _ := readyV2Fixture(t)
	if code, err := EnrollRecovery(path, password); code != "" || !errors.Is(err, ErrRecoveryUnsupported) {
		t.Fatalf("non-Linux recovery enrollment was enabled: %v", err)
	}
	if code, err := RotateRecovery(path, password); code != "" || !errors.Is(err, ErrRecoveryUnsupported) {
		t.Fatalf("non-Linux recovery rotation was enabled: %v", err)
	}
	if code, err := RecoverPassword(path, "not a code", "new sufficiently long password"); code != "" || !errors.Is(err, ErrRecoveryUnsupported) {
		t.Fatalf("non-Linux password recovery was enabled: %v", err)
	}
}
