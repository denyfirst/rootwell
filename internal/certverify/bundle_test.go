package certverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/limits"
)

func TestParseBundleRejectsUnsafeContents(t *testing.T) {
	chain := newTestChain(t, leafServerAuth)
	tests := []struct {
		name    string
		input   []byte
		role    bundleRole
		wantErr error
	}{
		{name: "empty trust", role: bundleTrustAnchors, wantErr: ErrInvalidTrustBundle},
		{name: "empty intermediates", role: bundleIntermediates, wantErr: ErrInvalidIntermediateBundle},
		{name: "leaf as root", input: certificatePEM(chain.leafDER), role: bundleTrustAnchors, wantErr: ErrRootNotCA},
		{name: "intermediate as root", input: chain.intermediatePEM, role: bundleTrustAnchors, wantErr: ErrRootNotSelfSigned},
		{name: "root as intermediate", input: chain.rootPEM, role: bundleIntermediates, wantErr: ErrIntermediateSelfSigned},
		{name: "duplicate root", input: append(append([]byte{}, chain.rootPEM...), chain.rootPEM...), role: bundleTrustAnchors, wantErr: ErrDuplicateCertificate},
		{name: "wrong PEM type", input: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), role: bundleTrustAnchors, wantErr: ErrInvalidTrustBundle},
		{name: "PEM headers", input: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Unsafe": "value"}, Bytes: chain.rootDER}), role: bundleTrustAnchors, wantErr: ErrInvalidTrustBundle},
		{name: "leading junk", input: append([]byte("junk\n"), chain.rootPEM...), role: bundleTrustAnchors, wantErr: ErrInvalidTrustBundle},
		{name: "trailing junk", input: append(append([]byte{}, chain.rootPEM...), []byte("junk")...), role: bundleTrustAnchors, wantErr: ErrInvalidTrustBundle},
		{name: "oversized", input: bytes.Repeat([]byte{'x'}, int(limits.MaxInputBytes)+1), role: bundleTrustAnchors, wantErr: ErrBundleResourceLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseBundle(test.input, test.role)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("parseBundle() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestParseBundleEnforcesCertificateCountLimit(t *testing.T) {
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	var bundle []byte
	for index := 0; index < 65; index++ {
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(index + 1)),
			Subject:               pkix.Name{CommonName: "Rootwell Count Test Root"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		bundle = append(bundle, certificatePEM(der)...)
	}

	if _, err := parseBundle(bundle, bundleTrustAnchors); !errors.Is(err, ErrBundleResourceLimit) {
		t.Fatalf("parseBundle() error = %v, want %v", err, ErrBundleResourceLimit)
	}
}

func TestBundlesOverlap(t *testing.T) {
	chain := newTestChain(t, leafServerAuth)
	root := parseCertificate(t, chain.rootDER)
	if !bundlesOverlap([]*x509.Certificate{root}, []*x509.Certificate{root}) {
		t.Fatal("bundlesOverlap() = false, want true")
	}
	if bundlesOverlap([]*x509.Certificate{root}, nil) {
		t.Fatal("bundlesOverlap() = true for disjoint bundles")
	}
}

func FuzzParseCertificateBundle(f *testing.F) {
	chain := newTestChain(f, leafServerAuth)
	f.Add(chain.rootPEM, uint8(0))
	f.Add(chain.intermediatePEM, uint8(1))
	f.Add([]byte("not a bundle"), uint8(0))

	f.Fuzz(func(t *testing.T, input []byte, roleByte uint8) {
		role := bundleTrustAnchors
		if roleByte%2 == 1 {
			role = bundleIntermediates
		}
		certificates, err := parseBundle(input, role)
		if err != nil {
			return
		}
		if len(certificates) == 0 || len(certificates) > limits.MaxCertificatesPerBundle {
			t.Fatalf("successful bundle count = %d", len(certificates))
		}
		for _, certificate := range certificates {
			if !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
				t.Fatal("successful bundle contains a non-CA certificate")
			}
		}
	})
}
