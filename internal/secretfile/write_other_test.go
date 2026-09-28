//go:build !linux

package secretfile

import (
	"errors"
	"testing"
)

func TestNonLinuxSecretOutputFailsClosed(t *testing.T) {
	if err := Preflight("ignored.p12"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("secret preflight unexpectedly enabled: %v", err)
	}
	if err := WriteNew("ignored.p12", []byte("secret")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("secret output unexpectedly enabled: %v", err)
	}
}
