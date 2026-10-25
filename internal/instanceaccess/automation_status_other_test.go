//go:build !linux

package instanceaccess

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeAutomationStatusRefusesBeforeFilesystem(t *testing.T) {
	if s, err := ReadAutomationStatus(filepath.Join(t.TempDir(), "absent"), nil, nil, [32]byte{}, time.Now()); !errors.Is(err, ErrRecoveryUnsupported) || s.Generation != 0 || s.Certificates != nil {
		t.Fatal("native status custody enabled")
	}
}
