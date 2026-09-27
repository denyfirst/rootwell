package instanceaccess

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func recoveryFixture(t *testing.T) ([]byte, []byte, []byte, string) {
	t.Helper()
	id := bytes.Repeat([]byte{0x31}, 16)
	key := bytes.Repeat([]byte{0x7a}, 32)
	wrap, code, err := CreateRecoveryWrap(id, key)
	if err != nil {
		t.Fatal(err)
	}
	return id, key, wrap, code
}

func TestRecoveryWrapRoundTripIsRandomAndBoundToInstallation(t *testing.T) {
	id, key, wrap, code := recoveryFixture(t)
	if len(wrap) != recoverySize || len(code) != 64 || bytes.Contains(wrap, key) || bytes.Contains(wrap, []byte(code)) {
		t.Fatal("recovery wrap has invalid form or exposes a secret")
	}
	opened, err := OpenRecoveryWrap(wrap, code, id)
	if err != nil || !bytes.Equal(opened, key) {
		t.Fatalf("correct recovery failed: %v", err)
	}
	otherWrap, otherCode, err := CreateRecoveryWrap(id, key)
	if err != nil || bytes.Equal(wrap, otherWrap) || code == otherCode {
		t.Fatalf("recovery material reused: %v", err)
	}
	if got, err := OpenRecoveryWrap(wrap, otherCode, id); !errors.Is(err, ErrInvalidRecovery) || got != nil {
		t.Fatalf("unrelated code recovered key: %v", err)
	}
	otherID := bytes.Repeat([]byte{0x32}, 16)
	if got, err := OpenRecoveryWrap(wrap, code, otherID); !errors.Is(err, ErrInvalidRecovery) || got != nil {
		t.Fatalf("other installation recovered key: %v", err)
	}
	forged := append([]byte(nil), wrap...)
	copy(forged[len(recoveryMagic):len(recoveryMagic)+16], otherID)
	if got, err := OpenRecoveryWrap(forged, code, otherID); !errors.Is(err, ErrInvalidRecovery) || got != nil {
		t.Fatalf("rewritten installation ID recovered key: %v", err)
	}
}

func TestRecoveryWrapRejectsTamperingAndMalformedInputs(t *testing.T) {
	id, _, wrap, code := recoveryFixture(t)
	for i := range wrap {
		changed := append([]byte(nil), wrap...)
		changed[i] ^= 1
		if got, err := OpenRecoveryWrap(changed, code, id); !errors.Is(err, ErrInvalidRecovery) || got != nil {
			t.Fatalf("tampered byte %d recovered key: %v", i, err)
		}
	}
	for _, body := range [][]byte{nil, wrap[:len(wrap)-1], append(append([]byte(nil), wrap...), 0)} {
		if got, err := OpenRecoveryWrap(body, code, id); !errors.Is(err, ErrInvalidRecovery) || got != nil {
			t.Fatalf("malformed length recovered key: %v", err)
		}
	}
	for _, badCode := range []string{"", "wrong", strings.ToUpper(code), strings.Replace(code, "-", "", 1), code[:len(code)-1] + "!"} {
		if got, err := OpenRecoveryWrap(wrap, badCode, id); !errors.Is(err, ErrInvalidRecovery) || got != nil {
			t.Fatalf("malformed code recovered key: %v", err)
		}
	}
	if got, err := OpenRecoveryWrap(wrap, code, nil); !errors.Is(err, ErrInvalidRecoveryInput) || got != nil {
		t.Fatalf("missing expected ID recovered key: %v", err)
	}
	if wrap, code, err := CreateRecoveryWrap(nil, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, ErrInvalidRecoveryInput) || wrap != nil || code != "" {
		t.Fatalf("missing ID made a recovery code: %v", err)
	}
	if wrap, code, err := CreateRecoveryWrap(id, bytes.Repeat([]byte{1}, 31)); !errors.Is(err, ErrInvalidRecoveryInput) || wrap != nil || code != "" {
		t.Fatalf("short data key made a recovery code: %v", err)
	}
}

func FuzzOpenRecoveryWrap(f *testing.F) {
	f.Add([]byte(""), "", []byte(""))
	f.Add([]byte(recoveryMagic), "wrong", bytes.Repeat([]byte{1}, 16))
	f.Fuzz(func(t *testing.T, wrap []byte, code string, id []byte) {
		if len(wrap) > 1024 || len(code) > 1024 || len(id) > 1024 {
			return
		}
		_, _ = OpenRecoveryWrap(wrap, code, id)
	})
}
