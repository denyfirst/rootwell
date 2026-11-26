// Package pfxfixture builds synthetic PFX files for tests from parts, so
// tests reach layouts that no encoder writes: the Windows bag order, other
// MAC digests, unknown bags and attributes, more safes. It is imported only
// by _test.go files (TestPFXFixtureBuilderIsTestOnly); no binary contains it.
//
// Its RFC 7292 appendix B key derivation exists to make fixtures only. Every
// ordinary layout it builds is also opened by the pinned decoder
// (TestBuilderAgreesWithPinnedDecoder), so the fixtures are real PFX files.
package pfxfixture

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- builds the legacy 3DES test fixtures that Windows and Java write.
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- legacy PKCS#12 MACs and key derivation use SHA-1.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"hash"
	"testing"
	"unicode/utf16"
)

var (
	OIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	OIDHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	OIDHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	OIDHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	OIDHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	OIDKeyBag       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	OIDShroudedKey  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	OIDCertBag      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	OIDCRLBag       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 4}
	OIDSecretBag    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 5}
	OIDNestedSafe   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
	OIDX509Cert     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	OIDSDSICert     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 2}
	OIDLocalKeyID   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	OIDMicrosoftCSP = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 17, 1}
	// OIDMachineKeySet marks a Windows machine key; the strict lister of the
	// pinned decoder cannot name it.
	OIDMachineKeySet = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 17, 2}
	// OIDExtendedProperty is one of the Windows certificate properties written
	// when "Export all extended properties" is ticked.
	OIDExtendedProperty = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 17, 3, 20}

	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBES2                         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidAES128CBC                     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC                     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC                     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// Protection describes one password-based encryption.
type Protection struct {
	Legacy3DES bool
	AESKey     int                   // 16, 24 or 32 for PBES2
	PRF        asn1.ObjectIdentifier // nil leaves the PRF out (HMAC-SHA-1)
	PRFParams  []byte                // nil writes NULL; empty writes nothing
	KeyLength  int                   // the PBKDF2 keyLength field; 0 leaves it out
	Iterations int
	SaltBytes  int
	IVBytes    int
	TrimCipher bool // drop one byte of ciphertext
}

// Modern is what OpenSSL 3 writes: PBES2, PBKDF2-HMAC-SHA-256, AES-256-CBC.
func Modern() Protection {
	return Protection{AESKey: 32, PRF: OIDHMACSHA256, Iterations: 2048, SaltBytes: 16, IVBytes: 16}
}

// DES is what Windows writes for "TripleDES-SHA1".
func DES() Protection {
	return Protection{Legacy3DES: true, Iterations: 2000, SaltBytes: 8}
}

// Bag is one PKCS#12 SafeBag.
type Bag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue `asn1:"tag:0,explicit"`
	Attributes []Attribute   `asn1:"set,optional"`
}

// Attribute is one bag attribute.
type Attribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// Safe is one item of the authenticated safe; nil Encrypted leaves it plain.
type Safe struct {
	Encrypted *Protection
	Bags      []Bag
}

// Spec is a whole PFX.
type Spec struct {
	Password       string
	AbsentPassword bool // the MAC and 3DES are keyed with no password bytes
	NoMAC          bool
	MACDigest      asn1.ObjectIdentifier // nil means SHA-256
	MACIterations  int                   // 0 means 2048
	Safes          []Safe
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type pbeParams struct {
	Salt       []byte
	Iterations int
}

func bmp(password string) []byte {
	out := make([]byte, 0, 2*len(password)+2)
	for _, unit := range utf16.Encode([]rune(password)) {
		out = append(out, byte(unit>>8), byte(unit))
	}
	return append(out, 0, 0)
}

func (spec Spec) passwordBytes() []byte {
	if spec.AbsentPassword {
		return nil
	}
	return bmp(spec.Password)
}

// kdf is RFC 7292 appendix B.2, for making fixtures only.
func kdf(newHash func() hash.Hash, v int, salt, password []byte, iterations int, id byte, size int) []byte {
	fill := func(in []byte) []byte {
		if len(in) == 0 {
			return nil
		}
		out := make([]byte, v*((len(in)+v-1)/v))
		for i := range out {
			out[i] = in[i%len(in)]
		}
		return out
	}
	diversifier := bytes.Repeat([]byte{id}, v)
	input := append(fill(salt), fill(password)...)
	var output []byte
	for len(output) < size {
		h := newHash()
		h.Write(diversifier)
		h.Write(input)
		block := h.Sum(nil)
		for round := 1; round < iterations; round++ {
			h = newHash()
			h.Write(block)
			block = h.Sum(nil)
		}
		output = append(output, block...)
		increment := fill(block)[:v]
		for start := 0; start < len(input); start += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				sum := int(input[start+k]) + int(increment[k]) + carry
				input[start+k] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	return output[:size]
}

// Marshal is asn1.Marshal that fails the test instead of returning an error.
func Marshal(t testing.TB, value any) []byte {
	t.Helper()
	out, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func random(t testing.TB, size int) []byte {
	t.Helper()
	out := make([]byte, size)
	if _, err := rand.Read(out); err != nil {
		t.Fatal(err)
	}
	return out
}

func pad(plaintext []byte, block int) []byte {
	n := block - len(plaintext)%block
	return append(bytes.Clone(plaintext), bytes.Repeat([]byte{byte(n)}, n)...)
}

// encrypt returns the AlgorithmIdentifier and ciphertext for one protection.
func (spec Spec) encrypt(t testing.TB, p Protection, plaintext []byte) (pkix.AlgorithmIdentifier, []byte) {
	t.Helper()
	salt := random(t, p.SaltBytes)
	var algorithm pkix.AlgorithmIdentifier
	var ciphertext []byte
	if p.Legacy3DES {
		password := spec.passwordBytes()
		key := kdf(sha1.New, 64, salt, password, p.Iterations, 1, 24)
		iv := kdf(sha1.New, 64, salt, password, p.Iterations, 2, 8)
		block, err := des.NewTripleDESCipher(key) // #nosec G401 -- a legacy 3DES test fixture.
		if err != nil {
			t.Fatal(err)
		}
		ciphertext = pad(plaintext, 8)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, ciphertext)
		algorithm = pkix.AlgorithmIdentifier{Algorithm: oidPBEWithSHAAnd3KeyTripleDESCBC,
			Parameters: asn1.RawValue{FullBytes: Marshal(t, pbeParams{Salt: salt, Iterations: p.Iterations})}}
	} else {
		prf := func() hash.Hash { return sha1.New() } // #nosec G401 -- the PBKDF2 default PRF, for a fixture.
		switch {
		case p.PRF.Equal(OIDHMACSHA256):
			prf = sha256.New
		case p.PRF.Equal(OIDHMACSHA512):
			prf = sha512.New
		case p.PRF.Equal(OIDHMACSHA384):
			prf = sha512.New384
		}
		key, err := pbkdf2.Key(prf, spec.Password, salt, p.Iterations, p.AESKey)
		if err != nil {
			t.Fatal(err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		iv := random(t, 16)
		ciphertext = pad(plaintext, 16)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, ciphertext)
		saltValue := asn1.RawValue{FullBytes: Marshal(t, salt)}
		var kdfBytes []byte
		switch {
		case p.PRF == nil && p.KeyLength == 0:
			kdfBytes = Marshal(t, struct {
				Salt       asn1.RawValue
				Iterations int
			}{saltValue, p.Iterations})
		case p.PRF == nil:
			kdfBytes = Marshal(t, struct {
				Salt       asn1.RawValue
				Iterations int
				KeyLength  int
			}{saltValue, p.Iterations, p.KeyLength})
		default:
			prfID := asn1.RawValue{FullBytes: Marshal(t, pkix.AlgorithmIdentifier{Algorithm: p.PRF, Parameters: asn1.NullRawValue})}
			switch {
			case p.PRFParams != nil && len(p.PRFParams) == 0:
				prfID.FullBytes = Marshal(t, struct{ Algorithm asn1.ObjectIdentifier }{p.PRF})
			case p.PRFParams != nil:
				prfID.FullBytes = Marshal(t, pkix.AlgorithmIdentifier{Algorithm: p.PRF, Parameters: asn1.RawValue{FullBytes: p.PRFParams}})
			}
			if p.KeyLength != 0 {
				kdfBytes = Marshal(t, struct {
					Salt       asn1.RawValue
					Iterations int
					KeyLength  int
					PRF        asn1.RawValue
				}{saltValue, p.Iterations, p.KeyLength, prfID})
			} else {
				kdfBytes = Marshal(t, struct {
					Salt       asn1.RawValue
					Iterations int
					PRF        asn1.RawValue
				}{saltValue, p.Iterations, prfID})
			}
		}
		cipherOID := map[int]asn1.ObjectIdentifier{16: oidAES128CBC, 24: oidAES192CBC, 32: oidAES256CBC}[p.AESKey]
		ivBytes := iv
		if p.IVBytes != 16 {
			ivBytes = random(t, p.IVBytes)
		}
		params := struct {
			KDF    pkix.AlgorithmIdentifier
			Cipher pkix.AlgorithmIdentifier
		}{
			pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfBytes}},
			pkix.AlgorithmIdentifier{Algorithm: cipherOID, Parameters: asn1.RawValue{FullBytes: Marshal(t, ivBytes)}},
		}
		algorithm = pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: Marshal(t, params)}}
	}
	if p.TrimCipher {
		ciphertext = ciphertext[:len(ciphertext)-1]
	}
	return algorithm, ciphertext
}

// Explicit wraps DER in a [0] EXPLICIT tag.
func Explicit(inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}
}

// Attr is a bag attribute with the given DER values.
func Attr(id asn1.ObjectIdentifier, values ...[]byte) Attribute {
	return Attribute{ID: id, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: bytes.Join(values, nil)}}
}

// LocalKeyID is the attribute that pairs a key with its certificate.
func LocalKeyID(t testing.TB) Attribute {
	return Attr(OIDLocalKeyID, Marshal(t, []byte{1, 0, 0, 0}))
}

// CSPName names a Windows key provider, as Windows does on key bags.
func CSPName(t testing.TB) Attribute {
	return Attr(OIDMicrosoftCSP, Marshal(t, asn1.RawValue{Tag: asn1.TagBMPString, Bytes: []byte{0, 'C', 0, 'S', 0, 'P'}}))
}

// CertificateBag holds one X.509 certificate.
func CertificateBag(t testing.TB, der []byte, attributes ...Attribute) Bag {
	value := Marshal(t, struct {
		ID   asn1.ObjectIdentifier
		Data []byte `asn1:"tag:0,explicit"`
	}{OIDX509Cert, der})
	return Bag{ID: OIDCertBag, Value: Explicit(value), Attributes: attributes}
}

// KeyBag holds one key, shrouded with p under the spec's password.
func (spec Spec) KeyBag(t testing.TB, key crypto.Signer, p Protection, attributes ...Attribute) Bag {
	t.Helper()
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	algorithm, ciphertext := spec.encrypt(t, p, plain)
	value := Marshal(t, struct {
		Algorithm pkix.AlgorithmIdentifier
		Bytes     []byte
	}{algorithm, ciphertext})
	return Bag{ID: OIDShroudedKey, Value: Explicit(value), Attributes: attributes}
}

// OtherBag is a bag of another kind with a small synthetic value.
func OtherBag(t testing.TB, id asn1.ObjectIdentifier) Bag {
	return Bag{ID: id, Value: Explicit(Marshal(t, []byte("synthetic other bag")))}
}

// Windows is the layout Windows and .NET write: the shrouded key in an
// unencrypted safe first, then the certificates, issuer first, in a safe
// encrypted with 3DES, under a SHA-1 MAC.
func Windows(t testing.TB, leaf, issuer *x509.Certificate, key crypto.Signer, password string, keyAttributes ...Attribute) Spec {
	spec := Spec{Password: password, MACDigest: OIDSHA1, MACIterations: 2000}
	p := DES()
	if keyAttributes == nil {
		keyAttributes = []Attribute{LocalKeyID(t), CSPName(t)}
	}
	spec.Safes = []Safe{
		{Bags: []Bag{spec.KeyBag(t, key, p, keyAttributes...)}},
		{Encrypted: &p, Bags: []Bag{CertificateBag(t, issuer.Raw), CertificateBag(t, leaf.Raw, LocalKeyID(t))}},
	}
	return spec
}

// OpenSSL is the OpenSSL and Java layout: an encrypted certificate safe,
// leaf first, then the key in an unencrypted safe.
func OpenSSL(t testing.TB, leaf, issuer *x509.Certificate, key crypto.Signer, password string, p Protection, digest asn1.ObjectIdentifier) Spec {
	spec := Spec{Password: password, MACDigest: digest}
	spec.Safes = []Safe{
		{Encrypted: &p, Bags: []Bag{CertificateBag(t, leaf.Raw, LocalKeyID(t)), CertificateBag(t, issuer.Raw)}},
		{Bags: []Bag{spec.KeyBag(t, key, p, LocalKeyID(t))}},
	}
	return spec
}

// Build returns the PFX bytes.
func (spec Spec) Build(t testing.TB) []byte {
	t.Helper()
	var contents []contentInfo
	for _, s := range spec.Safes {
		plain := Marshal(t, s.Bags)
		if s.Encrypted == nil {
			contents = append(contents, contentInfo{ContentType: OIDData, Content: Explicit(Marshal(t, plain))})
			continue
		}
		algorithm, ciphertext := spec.encrypt(t, *s.Encrypted, plain)
		encrypted := struct {
			Version int
			Content struct {
				ContentType asn1.ObjectIdentifier
				Algorithm   pkix.AlgorithmIdentifier
				Bytes       []byte `asn1:"tag:0,optional"`
			}
		}{}
		encrypted.Content.ContentType = OIDData
		encrypted.Content.Algorithm = algorithm
		encrypted.Content.Bytes = ciphertext
		contents = append(contents, contentInfo{ContentType: OIDEncryptedData, Content: Explicit(Marshal(t, encrypted))})
	}
	authenticated := Marshal(t, contents)
	authSafe := contentInfo{ContentType: OIDData, Content: Explicit(Marshal(t, authenticated))}
	if spec.NoMAC {
		return Marshal(t, struct {
			Version  int
			AuthSafe contentInfo
		}{3, authSafe})
	}
	digest := spec.MACDigest
	if digest == nil {
		digest = OIDSHA256
	}
	newHash, v := sha256.New, 64
	switch {
	case digest.Equal(OIDSHA1):
		newHash = sha1.New
	case digest.Equal(OIDSHA384):
		newHash, v = sha512.New384, 128
	case digest.Equal(OIDSHA512):
		newHash, v = sha512.New, 128
	}
	iterations := spec.MACIterations
	if iterations == 0 {
		iterations = 2048
	}
	salt := random(t, 8)
	key := kdf(newHash, v, salt, spec.passwordBytes(), iterations, 3, newHash().Size())
	mac := hmac.New(newHash, key)
	mac.Write(authenticated)
	type digestInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}
	type macData struct {
		Mac        digestInfo
		MacSalt    []byte
		Iterations int
	}
	return Marshal(t, struct {
		Version  int
		AuthSafe contentInfo
		MacData  macData
	}{3, authSafe, macData{Mac: digestInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: digest, Parameters: asn1.NullRawValue}, Digest: mac.Sum(nil)}, MacSalt: salt, Iterations: iterations}})
}
