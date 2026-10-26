//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"
)

func TestNativeProviderReadRefusesBeforeFilesOrCallback(t *testing.T) {
	called := false
	err := RunStagingProviderRead("must-not-open", nil, nil, [32]byte{}, func() bool { called = true; return true }, func(func() bool) error { called = true; return nil })
	if !errors.Is(err, ErrRecoveryUnsupported) || called {
		t.Fatal("native provider custody did not refuse")
	}
}
