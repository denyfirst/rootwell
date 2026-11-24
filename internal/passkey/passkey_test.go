package passkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
)

const (
	rpID   = "rootwell.lan"
	origin = "https://rootwell.lan:4180"
)

// pair keeps map entries in the order a test writes them.
type pair struct{ k, v any }

// encode is a test-only CBOR writer, enough for what authenticators send.
func encode(v any) []byte {
	head := func(major byte, n uint64) []byte {
		switch {
		case n < 24:
			return []byte{major<<5 | byte(n)}
		case n < 1<<8:
			return []byte{major<<5 | 24, byte(n)}
		case n < 1<<16:
			return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
		default:
			return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
		}
	}
	switch x := v.(type) {
	case int:
		if x < 0 {
			return head(1, uint64(-1-x))
		}
		return head(0, uint64(x))
	case []byte:
		return append(head(2, uint64(len(x))), x...)
	case string:
		return append(head(3, uint64(len(x))), x...)
	case []pair:
		out := head(5, uint64(len(x)))
		for _, p := range x {
			out = append(append(out, encode(p.k)...), encode(p.v)...)
		}
		return out
	case []any:
		out := head(4, uint64(len(x)))
		for _, item := range x {
			out = append(out, encode(item)...)
		}
		return out
	case bool:
		if x {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	}
	panic("unsupported")
}

// authenticator is a software passkey.
type authenticator struct {
	alg   int
	key   crypto.Signer
	id    []byte
	count uint32
}

func newAuthenticator(t *testing.T, alg int) *authenticator {
	t.Helper()
	a := &authenticator{alg: alg, id: []byte("credential-" + big.NewInt(int64(-alg)).String())}
	var err error
	switch alg {
	case AlgES256:
		a.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgEdDSA:
		_, a.key, err = ed25519.GenerateKey(rand.Reader)
	case AlgRS256:
		a.key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (a *authenticator) coseKey() []pair {
	switch k := a.key.Public().(type) {
	case *ecdsa.PublicKey:
		raw, _ := k.Bytes()
		return []pair{{1, 2}, {3, AlgES256}, {-1, 1}, {-2, raw[1:33]}, {-3, raw[33:]}}
	case ed25519.PublicKey:
		return []pair{{1, 1}, {3, AlgEdDSA}, {-1, 6}, {-2, []byte(k)}}
	case *rsa.PublicKey:
		return []pair{{1, 3}, {3, AlgRS256}, {-1, k.N.Bytes()}, {-2, big.NewInt(int64(k.E)).Bytes()}}
	}
	return nil
}

func authData(name string, flags byte, count uint32, attested []byte) []byte {
	hash := sha256.Sum256([]byte(name))
	out := append(hash[:], flags)
	out = binary.BigEndian.AppendUint32(out, count)
	return append(out, attested...)
}

func (a *authenticator) attested(key []pair) []byte {
	out := make([]byte, 16) // AAGUID: zero, as with attestation "none"
	out = binary.BigEndian.AppendUint16(out, uint16(len(a.id)))
	out = append(out, a.id...)
	return append(out, encode(key)...)
}

func client(kind string, challenge []byte, at string) []byte {
	b, _ := json.Marshal(map[string]any{"type": kind, "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": at,
		"crossOrigin": false, "other_keys_can_be_added_here": "do not compare clientDataJSON against a template"})
	return b
}

func (a *authenticator) register(challenge []byte) (clientDataJSON, attestationObject []byte) {
	data := authData(rpID, flagUserPresent|flagUserVerified|flagAttested, a.count, a.attested(a.coseKey()))
	return client("webauthn.create", challenge, origin),
		encode([]pair{{"fmt", "none"}, {"attStmt", []pair{}}, {"authData", data}})
}

func (a *authenticator) sign(data, clientDataJSON []byte) []byte {
	clientHash := sha256.Sum256(clientDataJSON)
	message := append(bytes.Clone(data), clientHash[:]...)
	if a.alg == AlgEdDSA {
		sig, _ := a.key.Sign(rand.Reader, message, crypto.Hash(0))
		return sig
	}
	digest := sha256.Sum256(message)
	sig, _ := a.key.Sign(rand.Reader, digest[:], crypto.SHA256)
	return sig
}

func (a *authenticator) assert(challenge []byte) (clientDataJSON, data, signature []byte) {
	a.count++
	clientDataJSON = client("webauthn.get", challenge, origin)
	data = authData(rpID, flagUserPresent|flagUserVerified, a.count, nil)
	return clientDataJSON, data, a.sign(data, clientDataJSON)
}

func challenge(t *testing.T) []byte {
	t.Helper()
	c, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEachAlgorithmRegistersAndSignsIn(t *testing.T) {
	for _, alg := range []int{AlgES256, AlgEdDSA, AlgRS256} {
		a := newAuthenticator(t, alg)
		c := challenge(t)
		clientDataJSON, object := a.register(c)
		credential, err := VerifyRegistration(rpID, origin, c, clientDataJSON, object)
		if err != nil || credential.Algorithm != alg || !bytes.Equal(credential.ID, a.id) {
			t.Fatalf("alg %d: registration %+v: %v", alg, credential, err)
		}
		for range 2 {
			c = challenge(t)
			cd, data, sig := a.assert(c)
			count, err := VerifyAssertion(rpID, origin, c, credential, cd, data, sig)
			if err != nil || count != a.count {
				t.Fatalf("alg %d: sign-in: %d %v", alg, count, err)
			}
			credential.SignCount = count
		}
	}
}

func TestTheBrowsersRecordMustBeThisCeremonyOnThisOrigin(t *testing.T) {
	a := newAuthenticator(t, AlgES256)
	c := challenge(t)
	_, object := a.register(c)
	other := challenge(t)
	for name, cd := range map[string][]byte{
		"another challenge":  client("webauthn.create", other, origin),
		"another origin":     client("webauthn.create", c, "https://evil.example:4180"),
		"plain HTTP":         client("webauthn.create", c, "http://rootwell.lan:4180"),
		"a sign-in record":   client("webauthn.get", c, origin),
		"from another frame": []byte(`{"type":"webauthn.create","challenge":"` + base64.RawURLEncoding.EncodeToString(c) + `","origin":"` + origin + `","crossOrigin":true}`),
		"not JSON":           []byte("{"),
		"empty":              nil,
	} {
		if _, err := VerifyRegistration(rpID, origin, c, cd, object); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestTheAuthenticatorMustBeForThisNameAndVerifyThePerson(t *testing.T) {
	a := newAuthenticator(t, AlgES256)
	c := challenge(t)
	cd := client("webauthn.create", c, origin)
	key := a.attested(a.coseKey())
	for name, data := range map[string][]byte{
		"another name":        authData("evil.example", flagUserPresent|flagUserVerified|flagAttested, 0, key),
		"no user verified":    authData(rpID, flagUserPresent|flagAttested, 0, key),
		"no user present":     authData(rpID, flagUserVerified|flagAttested, 0, key),
		"no credential":       authData(rpID, flagUserPresent|flagUserVerified, 0, nil),
		"bytes after the key": append(authData(rpID, flagUserPresent|flagUserVerified|flagAttested, 0, key), 0),
		"too short":           []byte{1, 2, 3},
	} {
		object := encode([]pair{{"fmt", "none"}, {"attStmt", []pair{}}, {"authData", data}})
		if _, err := VerifyRegistration(rpID, origin, c, cd, object); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	good := authData(rpID, flagUserPresent|flagUserVerified|flagAttested, 0, key)
	for name, object := range map[string][]byte{
		"no format":         encode([]pair{{"attStmt", []pair{}}, {"authData", good}}),
		"no statement":      encode([]pair{{"fmt", "none"}, {"authData", good}}),
		"bytes after it":    append(encode([]pair{{"fmt", "none"}, {"attStmt", []pair{}}, {"authData", good}}), 0),
		"authData a string": encode([]pair{{"fmt", "none"}, {"attStmt", []pair{}}, {"authData", "x"}}),
	} {
		if _, err := VerifyRegistration(rpID, origin, c, cd, object); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Any attestation format is accepted and never read.
	packed := encode([]pair{{"fmt", "packed"}, {"attStmt", []pair{{"alg", -7}, {"sig", []byte("not checked")}}}, {"authData", good}})
	if _, err := VerifyRegistration(rpID, origin, c, cd, packed); err != nil {
		t.Fatalf("a packed statement: %v", err)
	}
}

func TestOnlyTheThreeAlgorithmsAreAccepted(t *testing.T) {
	a := newAuthenticator(t, AlgES256)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	c := challenge(t)
	cd := client("webauthn.create", c, origin)
	ec := a.coseKey()
	for name, key := range map[string][]pair{
		"P-384":           {{1, 2}, {3, -35}, {-1, 2}, {-2, make([]byte, 48)}, {-3, make([]byte, 48)}},
		"P-256 off curve": {{1, 2}, {3, AlgES256}, {-1, 1}, {-2, make([]byte, 32)}, {-3, make([]byte, 32)}},
		"ES256 on P-384":  {{1, 2}, {3, AlgES256}, {-1, 2}, ec[3], ec[4]},
		"RSA 1024":        {{1, 3}, {3, AlgRS256}, {-1, small.N.Bytes()}, {-2, []byte{1, 0, 1}}},
		"RSA even e":      {{1, 3}, {3, AlgRS256}, {-1, bytes.Repeat([]byte{0xff}, 256)}, {-2, []byte{2}}},
		"unknown kind":    {{1, 9}, {3, AlgES256}},
	} {
		data := authData(rpID, flagUserPresent|flagUserVerified|flagAttested, 0, a.attested(key))
		object := encode([]pair{{"fmt", "none"}, {"attStmt", []pair{}}, {"authData", data}})
		if _, err := VerifyRegistration(rpID, origin, c, cd, object); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestOnlyASignatureOfThisChallengeByThisPasskeyCounts(t *testing.T) {
	a := newAuthenticator(t, AlgES256)
	c := challenge(t)
	cd, object := a.register(c)
	credential, err := VerifyRegistration(rpID, origin, c, cd, object)
	if err != nil {
		t.Fatal(err)
	}
	c = challenge(t)
	cd, data, sig := a.assert(c)
	other := newAuthenticator(t, AlgES256)
	tampered := bytes.Clone(data)
	tampered[len(tampered)-1] ^= 1
	attested := authData(rpID, flagUserPresent|flagUserVerified|flagAttested, a.count, a.attested(a.coseKey()))
	for name, try := range map[string]func() error{
		"another key's signature": func() error {
			_, err := VerifyAssertion(rpID, origin, c, credential, cd, data, other.sign(data, cd))
			return err
		},
		"changed data": func() error { _, err := VerifyAssertion(rpID, origin, c, credential, cd, tampered, sig); return err },
		"another challenge": func() error {
			_, err := VerifyAssertion(rpID, origin, challenge(t), credential, cd, data, sig)
			return err
		},
		"a registration record": func() error {
			_, err := VerifyAssertion(rpID, origin, c, credential, client("webauthn.create", c, origin), data, sig)
			return err
		},
		"attested data": func() error {
			_, err := VerifyAssertion(rpID, origin, c, credential, cd, attested, a.sign(attested, cd))
			return err
		},
		"the wrong algorithm": func() error {
			wrong := credential
			wrong.Algorithm = AlgEdDSA
			_, err := VerifyAssertion(rpID, origin, c, wrong, cd, data, sig)
			return err
		},
	} {
		if err := try(); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := VerifyAssertion(rpID, origin, c, credential, cd, data, sig); err != nil {
		t.Fatalf("the real answer: %v", err)
	}
}

func TestACountThatDoesNotGrowIsRefused(t *testing.T) {
	a := newAuthenticator(t, AlgEdDSA)
	c := challenge(t)
	cd, object := a.register(c)
	credential, err := VerifyRegistration(rpID, origin, c, cd, object)
	if err != nil {
		t.Fatal(err)
	}
	credential.SignCount = 5
	for _, count := range []uint32{4, 5} {
		a.count = count - 1
		c = challenge(t)
		cd, data, sig := a.assert(c)
		if _, err := VerifyAssertion(rpID, origin, c, credential, cd, data, sig); !errors.Is(err, ErrRefused) {
			t.Fatalf("count %d after 5: %v", count, err)
		}
	}
	// An authenticator that keeps no count says 0 every time.
	credential.SignCount = 0
	for range 2 {
		c = challenge(t)
		cd = client("webauthn.get", c, origin)
		data := authData(rpID, flagUserPresent|flagUserVerified, 0, nil)
		if _, err := VerifyAssertion(rpID, origin, c, credential, cd, data, a.sign(data, cd)); err != nil {
			t.Fatalf("a passkey without a count: %v", err)
		}
	}
}

func TestCBORIsReadStrictly(t *testing.T) {
	deep := []byte{}
	for range maxDepth + 2 {
		deep = append(deep, 0x81)
	}
	deep = append(deep, 0x00)
	for name, data := range map[string][]byte{
		"indefinite bytes":  {0x5f, 0x41, 0x00, 0xff},
		"a tag":             {0xc0, 0x00},
		"a float":           {0xf9, 0x3c, 0x00},
		"duplicate keys":    {0xa2, 0x01, 0x00, 0x01, 0x00},
		"an array key":      {0xa1, 0x80, 0x00},
		"too deep":          deep,
		"length past end":   {0x5a, 0xff, 0xff, 0xff, 0xff},
		"bad UTF-8":         {0x62, 0xc3, 0x28},
		"too many items":    append([]byte{0x98, maxItems + 1}, make([]byte, maxItems+1)...),
		"a huge integer":    {0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"a reserved length": {0x1c},
		"nothing":           {},
	} {
		if _, _, err := decodeCBOR(data); err == nil {
			t.Fatalf("%s was read", name)
		}
	}
	value, rest, err := decodeCBOR(encode([]pair{{1, []any{"a", -2, true}}, {"k", []byte{9}}}))
	m, _ := value.(map[any]any)
	if err != nil || len(rest) != 0 || len(m) != 2 || m["k"].([]byte)[0] != 9 || m[int64(1)].([]any)[1] != int64(-2) {
		t.Fatalf("a good map: %#v %v", value, err)
	}
}

func FuzzDecodeCBOR(f *testing.F) {
	f.Add(encode([]pair{{"fmt", "none"}, {"attStmt", []pair{}}, {"authData", []byte{1, 2}}}))
	f.Add([]byte{0x5f, 0x41, 0x00, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, rest, err := decodeCBOR(data)
		if err == nil && len(rest) > len(data) {
			t.Fatal("read past the input")
		}
	})
}

func FuzzVerifyRegistration(f *testing.F) {
	a := &authenticator{alg: AlgEdDSA, id: []byte("seed")}
	_, a.key, _ = ed25519.GenerateKey(rand.Reader)
	c := make([]byte, ChallengeSize)
	cd, object := a.register(c)
	f.Add(cd, object)
	f.Fuzz(func(t *testing.T, cd, object []byte) {
		credential, err := VerifyRegistration(rpID, origin, c, cd, object)
		if err == nil && (len(credential.ID) == 0 || len(credential.PublicKey) == 0) {
			t.Fatal("an empty credential was accepted")
		}
	})
}
