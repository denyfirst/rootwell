//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"
)

func TestNativeStagingAccountStoreRefusesBeforeIOOrPermit(t *testing.T) {
	if s, gen, err := ReadStagingAccount("not-an-installation", nil, nil, [32]byte{}); !errors.Is(err, ErrRecoveryUnsupported) || s.State != "" || gen != 0 {
		t.Fatal("native account read accepted")
	}
	if s, gen, err := PrepareStagingAccount("not-an-installation", nil, nil, [32]byte{}, 1, func() bool { t.Fatal("native custody consulted write permit"); return true }); !errors.Is(err, ErrRecoveryUnsupported) || s.State != "" || gen != 0 {
		t.Fatal("native account custody accepted")
	}
}
