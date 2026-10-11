//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"
)

func TestNativeCertificateRequestRefusesBeforeFileOrPermission(t *testing.T) {
	called := false
	s, g, err := PrepareStagingCertificateRequest("nonexistent-rootwell-key-request", nil, nil, [32]byte{}, 10, func() bool { called = true; return true })
	if !errors.Is(err, ErrRecoveryUnsupported) || s.Prepared || g != 0 || called {
		t.Fatal("native request acquired custody")
	}
	o, s, g, err := ReadStagingOrderPreparation("nonexistent-rootwell-key-request", nil, nil, [32]byte{})
	if !errors.Is(err, ErrRecoveryUnsupported) || o.State != "" || s.Prepared || g != 0 {
		t.Fatal("native request read acquired custody")
	}
}
