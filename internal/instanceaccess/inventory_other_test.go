//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"
)

func TestNonLinuxDurableInventoryFailsClosed(t *testing.T) {
	if err := InitializeInventory("unused", "unused", "unused", "unused"); !errors.Is(err, ErrRecoveryUnsupported) {
		t.Fatal("non-Linux inventory initialized")
	}
	if records, _, err := ReadInventory("unused", nil, nil, [32]byte{}); !errors.Is(err, ErrRecoveryUnsupported) || records != nil {
		t.Fatal("non-Linux inventory read")
	}
	if records, _, err := AppendInventory("unused", nil, nil, [32]byte{}, nil, "", ""); !errors.Is(err, ErrRecoveryUnsupported) || records != nil {
		t.Fatal("non-Linux inventory wrote")
	}
	if err := ExportFullSnapshot("", "", "", ""); !errors.Is(err, ErrRecoveryUnsupported) {
		t.Fatal("non-Linux full backup exported")
	}
	if id, _, err := VerifyFullSnapshot("", "", SnapshotPassword); !errors.Is(err, ErrRecoveryUnsupported) || id != nil {
		t.Fatal("non-Linux full backup verified")
	}
	if err := RestoreFullSnapshot("", "", "", SnapshotPassword); !errors.Is(err, ErrRecoveryUnsupported) {
		t.Fatal("non-Linux full backup restored")
	}
}
