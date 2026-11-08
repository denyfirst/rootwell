package browserpfximport

import (
	"bytes"
	"testing"
)

func FuzzPFXImportNoPartialSecret(f *testing.F) {
	f.Add([]byte{0x30, 0x00}, []byte("synthetic"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----"), []byte("wrong"))
	f.Fuzz(func(t *testing.T, input, password []byte) {
		if len(input) > 8192 || len(password) > 128 {
			return
		}
		p, err := Prepare(input, password)
		defer p.Clear()
		if err != nil {
			if len(p.Certificate) != 0 || len(p.PrivateKey) != 0 || len(p.KeyPassword) != 0 || p.Fingerprint != "" {
				t.Fatal("partial preparation on refusal")
			}
			return
		}
		if !bytes.HasPrefix(p.PrivateKey, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) || bytes.Equal(p.KeyPassword, password) || len(p.KeyPassword) != 43 {
			t.Fatal("unsafe prepared key")
		}
	})
}
