//go:build !linux

package instanceaccess

import (
	"crypto"
	"errors"
	"testing"
)

func TestNativeIssuanceRefusesBeforeFilePermissionAndCallback(t *testing.T) {
	called := false
	s, g, err := RunStagingIssuance("nonexistent-rootwell-issuance", nil, nil, [32]byte{}, 1, false, func() bool { called = true; return true }, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (string, error) {
		called = true
		return "processing", nil
	})
	if !errors.Is(err, ErrRecoveryUnsupported) || s.State != "" || g != 0 || called {
		t.Fatal("native issuance obtained custody")
	}
	s, g, err = ReadStagingIssuance("nonexistent-rootwell-issuance", nil, nil, [32]byte{})
	if !errors.Is(err, ErrRecoveryUnsupported) || s.State != "" || g != 0 {
		t.Fatal("native issuance read obtained custody")
	}
	s, g, err = CompleteStagingIssuance("nonexistent-rootwell-completion", nil, nil, [32]byte{}, 1, nil, func() bool { called = true; return true })
	if !errors.Is(err, ErrRecoveryUnsupported) || s.State != "" || g != 0 || called {
		t.Fatal("native completion obtained custody")
	}
}
