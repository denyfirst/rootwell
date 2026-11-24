//go:build linux

package certstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/accountstore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
	"github.com/denyfirst/rootwell/internal/vault"
)

// The container drill (scripts/test-container-volume.sh) runs this test inside
// the image, one phase per run, against bind-mounted /data and /key. It never
// runs by itself: without the phase variable it skips.
const (
	drillData = "/data"
	drillKey  = "/key/instance.key"
)

func TestContainerVolumeDrill(t *testing.T) {
	phase := os.Getenv("ROOTWELL_VOLUME_DRILL_PHASE")
	if phase == "" {
		t.Skip("run by scripts/test-container-volume.sh inside the image")
	}
	switch phase {
	case "seed":
		drillSeed(t)
	case "reopen":
		drillReopen(t)
	case "busy":
		// rootwelld serve holds the vault: a second opener must be refused, not
		// share the file.
		key := drillReadKey(t)
		if v, err := vault.Open(drillData, key); err == nil {
			_ = v.Close()
			t.Fatal("the vault opened while the server held it")
		}
	case "unsafe":
		// The script made /data readable by others; the vault refuses it.
		key := drillReadKey(t)
		if v, err := vault.Open(drillData, key); err == nil {
			_ = v.Close()
			t.Fatal("the vault opened in a directory others can read")
		}
	default:
		t.Fatalf("unknown drill phase %q", phase)
	}
}

func drillReadKey(t *testing.T) []byte {
	t.Helper()
	key, err := vault.ReadKeyFile(drillKey)
	if err != nil {
		t.Fatalf("the instance key file did not read: %v", err)
	}
	return key
}

// drillSeed does what rootwelld init does, without a terminal, and saves one
// certificate with its key. The setup code goes to /recovery, so the script
// can check that the server never logs it.
func drillSeed(t *testing.T) {
	entries, err := os.ReadDir(drillData)
	if err != nil || len(entries) != 0 {
		t.Fatalf("the drill needs an empty /data: %v", err)
	}
	key, err := vault.NewInstanceKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.WriteKeyFile(drillKey, key); err != nil {
		t.Fatalf("key file: %v", err)
	}
	v, err := vault.Create(drillData, key)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	defer v.Close()
	setup, _, err := accountstore.New(v, time.Now).NewSetupCode("")
	if err != nil {
		t.Fatalf("setup code: %v", err)
	}
	if err := os.WriteFile(filepath.Join(drillData, "..", "recovery", "setup-code"), []byte(setup), 0o600); err != nil {
		t.Fatalf("the setup code for the log check: %v", err)
	}
	a := issue(t, "volume.example")
	if _, _, err := New(v).Save(1, a.certificate, a.key, nil, "Volume drill", "drill-host", a.fingerprint, false); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := os.WriteFile(filepath.Join(drillData, "..", "recovery", "fingerprint"), []byte(a.fingerprint), 0o600); err != nil {
		t.Fatalf("the fingerprint for the next phase: %v", err)
	}
}

// drillReopen opens what seed wrote, in a new container, as a restart does.
func drillReopen(t *testing.T) {
	fingerprint, err := os.ReadFile(filepath.Join(drillData, "..", "recovery", "fingerprint"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := vault.NewInstanceKey()
	if err != nil {
		t.Fatal(err)
	}
	if v, err := vault.Open(drillData, other); err == nil {
		_ = v.Close()
		t.Fatal("another key opened the vault")
	}
	v, err := vault.Open(drillData, drillReadKey(t))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer v.Close()
	s := New(v)
	records, generation, err := s.List()
	if err != nil || len(records) != 1 || records[0].Fingerprint != string(fingerprint) || records[0].Owner != "Volume drill" ||
		records[0].KeyStatus != "matched" {
		t.Fatalf("after reopening: %+v %v", records, err)
	}
	if err := s.WithCertificate(generation, string(fingerprint), func(r publicinventory.Record, key []byte) error {
		if len(key) == 0 || len(r.DER) == 0 {
			return errors.New("no key")
		}
		return nil
	}); err != nil {
		t.Fatalf("the key did not come back: %v", err)
	}
	if _, _, err := s.SetOwner(generation, string(fingerprint), "Volume drill, reopened"); err != nil {
		t.Fatalf("the reopened vault refused a change: %v", err)
	}
}
