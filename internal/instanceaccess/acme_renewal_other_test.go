//go:build !linux

package instanceaccess

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestNativeRenewalRefusesBeforeFilesAndPermit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	calls := 0
	permit := func() bool { calls++; return true }
	if s, g, err := ReadStagingRenewalResult(path, nil, nil, [32]byte{}, 14); !errors.Is(err, ErrRecoveryUnsupported) || s != nil || g != 0 {
		t.Fatal("native renewal result custody enabled")
	}
	if s, g, err := ReadStagingRenewalSource(path, nil, nil, [32]byte{}, 14, ""); !errors.Is(err, ErrRecoveryUnsupported) || s.Fingerprint != "" || g != 0 {
		t.Fatal("native source custody enabled")
	}
	if s, g, err := RunStagingRenewalOrder(path, nil, nil, [32]byte{}, 14, "", permit, nil); !errors.Is(err, ErrRecoveryUnsupported) || s.State != "" || g != 0 || calls != 0 {
		t.Fatal("native renewal borrowed authority")
	}
}
