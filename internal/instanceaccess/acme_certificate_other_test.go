//go:build !linux

package instanceaccess

import (
	"crypto"
	"github.com/denyfirst/rootwell/internal/acmestaging"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeCertificateRefusesBeforeFilePermissionAndConnector(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	called := false
	s, g, err := RunStagingCertificate(path, nil, nil, [32]byte{}, 11, false, func() bool { called = true; return true }, func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) (acmestaging.CertificateObservation, error) {
		called = true
		return acmestaging.CertificateObservation{}, nil
	})
	if err != ErrRecoveryUnsupported || s.State != "" || g != 0 || called {
		t.Fatal("native certificate gained authority")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("native certificate touched file")
	}
}
