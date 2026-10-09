//go:build !linux

package instanceaccess

import (
	"crypto"
	"errors"
	"testing"
)

func TestNativeStagingRegistrationRefusesBeforeIOPermitOrSigner(t *testing.T) {
	status, gen, err := RunStagingRegistration("must-not-touch", nil, nil, [32]byte{}, 1, "", false, func() bool { t.Fatal("native permit called"); return true }, func(crypto.Signer, string) (string, bool, error) {
		t.Fatal("native signer called")
		return "", false, nil
	})
	if !errors.Is(err, ErrRecoveryUnsupported) || status.State != "" || gen != 0 {
		t.Fatal("native registration accepted")
	}
}
