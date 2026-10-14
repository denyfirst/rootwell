//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"
)

func TestNativeCloudflareConfigRefusesBeforePermissionOrStorage(t *testing.T) {
	if s, gen, err := ReadCloudflareConfig("not-a-real-path", nil, nil, [32]byte{}); !errors.Is(err, ErrRecoveryUnsupported) || s.State != "" || gen != 0 {
		t.Fatal("native credential read accepted")
	}
	if s, gen, err := ChangeCloudflareConfig("not-a-real-path", nil, nil, [32]byte{}, 1, "", "", nil, false, func() bool { t.Fatal("native borrowed permission"); return true }); !errors.Is(err, ErrRecoveryUnsupported) || s.State != "" || gen != 0 {
		t.Fatal("native credential save accepted")
	}
}
