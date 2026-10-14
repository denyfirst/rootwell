//go:build !linux

package instanceaccess

import (
	"errors"
	"testing"

	"github.com/denyfirst/rootwell/internal/providerretry"
)

func TestNativeDNSPlanRefusesBeforeBorrowingPermission(t *testing.T) {
	permit := func() bool { t.Fatal("native borrowed permission"); return true }
	if s, gen, err := ReadStagingDNSPlan("not-real", nil, nil, [32]byte{}); !errors.Is(err, ErrRecoveryUnsupported) || s.Prepared || gen != 0 {
		t.Fatal("native read allowed")
	}
	if s, gen, err := PrepareStagingDNSPlan("not-real", nil, nil, [32]byte{}, 1, permit); !errors.Is(err, ErrRecoveryUnsupported) || s.Prepared || gen != 0 {
		t.Fatal("native plan allowed")
	}
	if a, s, gen, err := BeginStagingDNSAttempt("not-real", nil, nil, [32]byte{}, 1, 0, permit); !errors.Is(err, ErrRecoveryUnsupported) || a != nil || s.Prepared || gen != 0 {
		t.Fatal("native attempt allowed")
	}
	if s, gen, err := DeferStagingDNSAttempt("not-real", nil, nil, [32]byte{}, nil, providerretry.Hint{}, permit); !errors.Is(err, ErrRecoveryUnsupported) || s.Prepared || gen != 0 {
		t.Fatal("native wait write allowed")
	}
}
