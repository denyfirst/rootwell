//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"
	"time"
)

func TestNativeTimingReadinessRefusesBeforeFiles(t *testing.T) {
	p, err := ReadTimingReadiness("not-a-real-path", nil, nil, [32]byte{}, 13, "", time.Now())
	if !errors.Is(err, ErrRecoveryUnsupported) || p.CanStart || p.Generation != 0 || p.Timing.Fingerprint != "" {
		t.Fatal("native gained storage authority")
	}
}
