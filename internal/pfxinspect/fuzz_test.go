package pfxinspect

import "testing"

func FuzzPFXPreflight(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte("not a PFX"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_ = Preflight(input)
	})
}
