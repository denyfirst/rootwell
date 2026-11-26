package pfxinspect

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/denyfirst/rootwell/internal/pfxfixture"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// FuzzPFXPreflight starts from every accepted protection so mutations reach
// the widened grammar: legacy 3DES and RC2, PBES2 and the Windows layout.
func FuzzPFXPreflight(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte("not a PFX"))
	c := newChain(f, false)
	for _, encoder := range []*pkcs12.Encoder{pkcs12.LegacyRC2, pkcs12.LegacyDES, pkcs12.Modern2023} {
		if data, err := encoder.WithIterations(2).Encode(c.key, c.leaf, []*x509.Certificate{c.issuer}, "fuzz"); err == nil {
			f.Add(data)
		}
	}
	f.Add(pfxfixture.Windows(f, c.leaf, c.issuer, c.key, "fuzz").Build(f))
	f.Fuzz(func(t *testing.T, input []byte) {
		err := Preflight(input)
		if err != nil && !errors.Is(err, ErrUnsupported) {
			t.Fatalf("preflight refusal outside its family: %v", err)
		}
		if err == nil && !IsPFX(input) {
			t.Fatal("preflight accepted what IsPFX does not call a PFX")
		}
	})
}
