//go:build !linux

package instanceaccess

import (
	"crypto"
	"errors"
	"github.com/denyfirst/rootwell/internal/acmeorder"
	"testing"
)

func TestNativeDNSValidationRefusesBeforeFileOrCallback(t *testing.T) {
	called := false
	status, gen, err := RunStagingValidation("nonexistent-rootwell-validation-path", make([]byte, 32), make([]byte, 16), [32]byte{}, 1, false, func() bool { return true }, func(crypto.Signer, string, acmeorder.Instructions, []string, bool) (acmeorder.Validation, error) {
		called = true
		return acmeorder.Validation{}, nil
	})
	if !errors.Is(err, ErrRecoveryUnsupported) || status.State != "" || gen != 0 || called {
		t.Fatal("native custody acquired capability")
	}
}
