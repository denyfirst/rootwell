//go:build !linux

package instanceaccess

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeNewRequestRefusesBeforeFilesAndPermit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	called := false
	s, g, err := CloseStagingRequest(path, nil, nil, [32]byte{}, 13, func() bool { called = true; return true })
	if err != ErrRecoveryUnsupported || s.Reason != "" || g != 0 || called {
		t.Fatal("native close acquired authority")
	}
	if s, g, err := ReadNewStagingRequest(path, nil, nil, [32]byte{}); err != ErrRecoveryUnsupported || s.Reason != "" || g != 0 {
		t.Fatal("native status acquired files")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("native closure touched file")
	}
}
