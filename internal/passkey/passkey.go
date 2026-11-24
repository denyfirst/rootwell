// Package passkey checks WebAuthn passkeys (ADR 0088's phishing-resistant
// second factor): a passkey made for this site's name, by an authenticator
// that verified the person, signs a fresh challenge.
//
// Attestation is not trusted or required: Rootwell asks for none, accepts any
// format, and never reads the statement. What a passkey proves is that the
// same authenticator that was added signs again, for the same name, after
// the person unlocked it. It stores nothing; the account record keeps what it
// returns.
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
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
)

// ErrRefused hides why a passkey answer was refused.
var ErrRefused = errors.New("passkey refused")

// Algorithms Rootwell accepts, as COSE numbers: ES256, EdDSA and RS256.
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttested     = 0x40
	flagExtensions   = 0x80
	maxCredentialID  = 1023
	maxClientData    = 4096
	// ChallengeSize is the length of every challenge, in bytes.
	ChallengeSize = 32
)

// Credential is a passkey as an account keeps it.
type Credential struct {
	ID        []byte `json:"id"`
	PublicKey []byte `json:"public_key"` // SubjectPublicKeyInfo, DER
	Algorithm int    `json:"algorithm"`
	SignCount uint32 `json:"sign_count"`
}

// NewChallenge returns 32 random bytes.
func NewChallenge() ([]byte, error) {
	c := make([]byte, ChallengeSize)
	if _, err := rand.Read(c); err != nil {
		return nil, ErrRefused
	}
	return c, nil
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// checkClientData checks the browser's own record of the ceremony: its kind,
// the challenge this server sent, this exact origin, and no frame of
// another site. Extra members are allowed; browsers add some.
func checkClientData(raw []byte, kind, origin string, challenge []byte) error {
	if len(raw) == 0 || len(raw) > maxClientData || len(challenge) != ChallengeSize {
		return ErrRefused
	}
	var c clientData
	if json.Unmarshal(raw, &c) != nil || c.Type != kind || c.Origin != origin || c.CrossOrigin {
		return ErrRefused
	}
	got, err := base64.RawURLEncoding.Strict().DecodeString(c.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return ErrRefused
	}
	return nil
}

type authenticatorData struct {
	flags        byte
	signCount    uint32
	credentialID []byte
	key          map[any]any
}

// parseAuthenticatorData reads the authenticator's data for rpID. The person
// must have been present and verified (a PIN, a fingerprint or a face).
func parseAuthenticatorData(b []byte, rpID string, attested bool) (authenticatorData, error) {
	var a authenticatorData
	if len(b) < 37 {
		return a, ErrRefused
	}
	want := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(b[:32], want[:]) != 1 {
		return a, ErrRefused
	}
	a.flags, a.signCount = b[32], binary.BigEndian.Uint32(b[33:37])
	if a.flags&flagUserPresent == 0 || a.flags&flagUserVerified == 0 || (a.flags&flagAttested != 0) != attested {
		return a, ErrRefused
	}
	rest := b[37:]
	if attested {
		if len(rest) < 18 {
			return a, ErrRefused
		}
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n == 0 || n > maxCredentialID || n > len(rest) {
			return a, ErrRefused
		}
		a.credentialID = bytes.Clone(rest[:n])
		key, after, err := decodeCBOR(rest[n:])
		m, ok := key.(map[any]any)
		if err != nil || !ok {
			return a, ErrRefused
		}
		a.key, rest = m, after
	}
	if a.flags&flagExtensions != 0 {
		extensions, after, err := decodeCBOR(rest)
		if _, ok := extensions.(map[any]any); err != nil || !ok {
			return a, ErrRefused
		}
		rest = after
	}
	if len(rest) != 0 {
		return a, ErrRefused
	}
	return a, nil
}

func bytesOf(m map[any]any, key int64, size int) ([]byte, bool) {
	b, ok := m[key].([]byte)
	return b, ok && (size == 0 || len(b) == size)
}

// publicKey turns a COSE key into a key Go checks signatures with, and keeps
// only the three algorithms Rootwell accepts.
func publicKey(m map[any]any) (crypto.PublicKey, int, error) {
	kty, _ := m[int64(1)].(int64)
	alg, _ := m[int64(3)].(int64)
	switch {
	case kty == 2 && alg == AlgES256:
		crv, _ := m[int64(-1)].(int64)
		x, okX := bytesOf(m, -2, 32)
		y, okY := bytesOf(m, -3, 32)
		if crv != 1 || !okX || !okY {
			return nil, 0, ErrRefused
		}
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, 0, ErrRefused
		}
		return key, AlgES256, nil
	case kty == 1 && alg == AlgEdDSA:
		crv, _ := m[int64(-1)].(int64)
		x, ok := bytesOf(m, -2, ed25519.PublicKeySize)
		if crv != 6 || !ok {
			return nil, 0, ErrRefused
		}
		return ed25519.PublicKey(x), AlgEdDSA, nil
	case kty == 3 && alg == AlgRS256:
		n, okN := bytesOf(m, -1, 0)
		e, okE := bytesOf(m, -2, 0)
		if !okN || !okE || len(e) == 0 || len(e) > 4 {
			return nil, 0, ErrRefused
		}
		modulus := new(big.Int).SetBytes(n)
		exponent := int(new(big.Int).SetBytes(e).Int64())
		if modulus.BitLen() < 2048 || modulus.BitLen() > 8192 || exponent < 3 || exponent%2 == 0 {
			return nil, 0, ErrRefused
		}
		return &rsa.PublicKey{N: modulus, E: exponent}, AlgRS256, nil
	}
	return nil, 0, ErrRefused
}

// VerifyRegistration checks a new passkey's answer to challenge, made for
// rpID on origin, and returns the credential to keep.
func VerifyRegistration(rpID, origin string, challenge, clientDataJSON, attestationObject []byte) (Credential, error) {
	if checkClientData(clientDataJSON, "webauthn.create", origin, challenge) != nil {
		return Credential{}, ErrRefused
	}
	object, rest, err := decodeCBOR(attestationObject)
	m, ok := object.(map[any]any)
	if err != nil || !ok || len(rest) != 0 {
		return Credential{}, ErrRefused
	}
	// The format and its statement are read only to be sure they are there;
	// Rootwell trusts no attestation.
	if _, ok := m["fmt"].(string); !ok {
		return Credential{}, ErrRefused
	}
	if _, ok := m["attStmt"].(map[any]any); !ok {
		return Credential{}, ErrRefused
	}
	raw, ok := m["authData"].([]byte)
	if !ok {
		return Credential{}, ErrRefused
	}
	data, err := parseAuthenticatorData(raw, rpID, true)
	if err != nil {
		return Credential{}, err
	}
	key, alg, err := publicKey(data.key)
	if err != nil {
		return Credential{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return Credential{}, ErrRefused
	}
	return Credential{ID: data.credentialID, PublicKey: spki, Algorithm: alg, SignCount: data.signCount}, nil
}

// VerifyAssertion checks that credential signed challenge for rpID on origin,
// and returns its new signature count. A count that did not grow, where the
// authenticator keeps one, says the passkey may have been copied: refused.
func VerifyAssertion(rpID, origin string, challenge []byte, credential Credential, clientDataJSON, authenticatorDataBytes, signature []byte) (uint32, error) {
	if checkClientData(clientDataJSON, "webauthn.get", origin, challenge) != nil {
		return 0, ErrRefused
	}
	data, err := parseAuthenticatorData(authenticatorDataBytes, rpID, false)
	if err != nil {
		return 0, err
	}
	if (data.signCount != 0 || credential.SignCount != 0) && data.signCount <= credential.SignCount {
		return 0, ErrRefused
	}
	key, err := x509.ParsePKIXPublicKey(credential.PublicKey)
	if err != nil {
		return 0, ErrRefused
	}
	clientHash := sha256.Sum256(clientDataJSON)
	message := append(bytes.Clone(authenticatorDataBytes), clientHash[:]...)
	digest := sha256.Sum256(message)
	ok := false
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		ok = credential.Algorithm == AlgES256 && ecdsa.VerifyASN1(k, digest[:], signature)
	case ed25519.PublicKey:
		ok = credential.Algorithm == AlgEdDSA && ed25519.Verify(k, message, signature)
	case *rsa.PublicKey:
		ok = credential.Algorithm == AlgRS256 && rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], signature) == nil
	}
	if !ok {
		return 0, ErrRefused
	}
	return data.signCount, nil
}
