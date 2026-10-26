//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"

	"github.com/denyfirst/rootwell/internal/renewalrecord"
)

func TestNativeRenewalTimingRefusesBeforeFilesOrCallback(t *testing.T) {
	if s, g, err := ReadStagingRenewalTiming("not-a-real-path", nil, nil, [32]byte{}, 1, ""); !errors.Is(err, ErrRecoveryUnsupported) || s.Prepared || g != 0 {
		t.Fatal("native read gained custody")
	}
	if s, g, err := RunStagingRenewalTiming("not-a-real-path", nil, nil, [32]byte{}, 1, "", func() bool { t.Fatal("native permission called"); return true }, func(func() bool, []byte) (renewalrecord.Observation, error) {
		t.Fatal("native connector called")
		return renewalrecord.Observation{}, nil
	}); !errors.Is(err, ErrRecoveryUnsupported) || s.Prepared || g != 0 {
		t.Fatal("native writer gained custody")
	}
	if s, g, err := InterruptStagingRenewalTiming("not-a-real-path", nil, nil, [32]byte{}, 1, "", nil); !errors.Is(err, ErrRecoveryUnsupported) || s.Prepared || g != 0 {
		t.Fatal("native retirement gained custody")
	}
}
