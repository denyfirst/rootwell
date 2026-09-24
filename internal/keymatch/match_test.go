package keymatch

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/limits"
)

func TestMatchSupportedPrivateKeyEncodings(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPKCS8, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	ed25519PKCS8, err := x509.MarshalPKCS8PrivateKey(ed25519Key)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaSEC1, err := x509.MarshalECPrivateKey(ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		key            crypto.Signer
		certificatePEM bool
		input          []byte
		wantEncoding   Encoding
		wantAlgorithm  string
	}{
		{name: "pkcs8 rsa pem", key: rsaKey, certificatePEM: true, input: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaPKCS8}), wantEncoding: EncodingPKCS8PEM, wantAlgorithm: "RSA"},
		{name: "pkcs8 ecdsa der", key: ecdsaKey, input: ecdsaPKCS8, wantEncoding: EncodingPKCS8DER, wantAlgorithm: "ECDSA"},
		{name: "pkcs8 ed25519 pem", key: ed25519Key, input: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ed25519PKCS8}), wantEncoding: EncodingPKCS8PEM, wantAlgorithm: "Ed25519"},
		{name: "pkcs1 pem", key: rsaKey, input: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), wantEncoding: EncodingPKCS1PEM, wantAlgorithm: "RSA"},
		{name: "pkcs1 der", key: rsaKey, input: x509.MarshalPKCS1PrivateKey(rsaKey), wantEncoding: EncodingPKCS1DER, wantAlgorithm: "RSA"},
		{name: "sec1 pem", key: ecdsaKey, input: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaSEC1}), wantEncoding: EncodingSEC1PEM, wantAlgorithm: "ECDSA"},
		{name: "sec1 der", key: ecdsaKey, certificatePEM: true, input: ecdsaSEC1, wantEncoding: EncodingSEC1DER, wantAlgorithm: "ECDSA"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificate := testCertificate(t, test.key)
			if test.certificatePEM {
				certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
			}
			result, err := Match(certificate, test.input)
			if err != nil {
				t.Fatalf("Match() error = %v", err)
			}
			if !result.Match {
				t.Fatal("Match() reported a mismatch for corresponding material")
			}
			if result.PrivateKeyEncoding != test.wantEncoding || result.PrivateKeyAlgorithm != test.wantAlgorithm {
				t.Fatalf("Match() key metadata = %q/%q, want %q/%q", result.PrivateKeyEncoding, result.PrivateKeyAlgorithm, test.wantEncoding, test.wantAlgorithm)
			}
			if result.PublicKeySHA256 == "" || result.PublicKeyBits == 0 {
				t.Fatalf("Match() omitted public metadata: %+v", result)
			}
		})
	}
}

func TestMatchReportsMismatchAsVerdict(t *testing.T) {
	_, certificateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Match(testCertificate(t, certificateKey), otherDER)
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if result.Match {
		t.Fatal("Match() accepted a different private key")
	}
}

func TestMatchRejectsUnsafePrivateKeyInputs(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := testCertificate(t, signer)
	validDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x25519DER, err := x509.MarshalPKCS8PrivateKey(x25519)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{name: "empty", wantErr: ErrEmptyPrivateKey},
		{name: "whitespace", input: []byte(" \n\t"), wantErr: ErrEmptyPrivateKey},
		{name: "oversized", input: bytes.Repeat([]byte{'x'}, int(limits.MaxPrivateKeyBytes)+1), wantErr: ErrPrivateKeyTooLarge},
		{name: "malformed der", input: []byte{0x30, 0x02, 0x01}, wantErr: ErrInvalidPrivateKey},
		{name: "trailing der", input: append(append([]byte(nil), validDER...), 0), wantErr: ErrInvalidPrivateKey},
		{name: "multiple pem blocks", input: append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: validDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: validDER})...), wantErr: ErrInvalidPrivateKey},
		{name: "wrong pem label", input: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: validDER}), wantErr: ErrUnsupportedPrivateKeyFormat},
		{name: "encrypted pkcs8", input: pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{0x30, 0}}), wantErr: ErrEncryptedPrivateKey},
		{name: "legacy encrypted pem", input: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00000000000000000000000000000000"}, Bytes: []byte{1, 2, 3}}), wantErr: ErrEncryptedPrivateKey},
		{name: "unsupported x25519", input: x25519DER, wantErr: ErrUnsupportedPrivateKey},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Match(certificate, test.input)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Match() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestMatchRejectsInvalidCertificateWithoutParsingKey(t *testing.T) {
	secret := bytes.Repeat([]byte("sensitive-private-key"), 8)
	_, err := Match([]byte("not a certificate"), secret)
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("Match() error = %v, want ErrInvalidCertificate", err)
	}
}

func TestMatchRejectsOversizedRSABeforePrivateArithmetic(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := testCertificate(t, signer)
	oversizedModulus := new(big.Int).Lsh(big.NewInt(1), limits.MaxPrivateKeyBits)
	pkcs1DER, err := asn1.Marshal(struct {
		Version int
		N       *big.Int
		E       int
		D       *big.Int
		P       *big.Int
		Q       *big.Int
		Dp      *big.Int
		Dq      *big.Int
		Qinv    *big.Int
	}{
		N: oversizedModulus, E: 65537, D: big.NewInt(1), P: big.NewInt(1), Q: big.NewInt(1),
		Dp: big.NewInt(1), Dq: big.NewInt(1), Qinv: big.NewInt(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: rsaEncryptionOID, Parameters: asn1.NullRawValue},
		PrivateKey: pkcs1DER,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, input := range [][]byte{pkcs1DER, pkcs8DER} {
		if int64(len(input)) > limits.MaxPrivateKeyBytes {
			t.Fatalf("test input unexpectedly exceeds file limit: %d bytes", len(input))
		}
		_, err := Match(certificate, input)
		if !errors.Is(err, ErrPrivateKeyResourceLimit) {
			t.Fatalf("Match() error = %v, want ErrPrivateKeyResourceLimit", err)
		}
	}
}

func TestMatchRejectsPKCS8ExtraField(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := testCertificate(t, signer)
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	var sequence asn1.RawValue
	if _, err := asn1.Unmarshal(der, &sequence); err != nil {
		t.Fatal(err)
	}
	contents := append(append([]byte(nil), sequence.Bytes...), 0xa0, 0x00)
	malformed, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: contents})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Match(certificate, malformed)
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("Match() error = %v, want ErrInvalidPrivateKey", err)
	}
}

func TestMatchRejectsPKCS8AlgorithmExtraField(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := privateKeyFields(der)
	if err != nil {
		t.Fatal(err)
	}
	algorithm, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(append([]byte(nil), fields[1].Bytes...), 0x05, 0x00),
	})
	if err != nil {
		t.Fatal(err)
	}
	contents := append(append(append([]byte(nil), fields[0].FullBytes...), algorithm...), fields[2].FullBytes...)
	malformed, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: contents})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Match(testCertificate(t, signer), malformed)
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("Match() error = %v, want ErrInvalidPrivateKey", err)
	}
}

func TestMatchRejectsPKCS1AndSEC1ExtraFields(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name string
		key  crypto.Signer
		der  []byte
	}{
		{name: "pkcs1", key: rsaKey, der: x509.MarshalPKCS1PrivateKey(rsaKey)},
		{name: "sec1", key: ecdsaKey, der: sec1},
	} {
		t.Run(item.name, func(t *testing.T) {
			var sequence asn1.RawValue
			if _, err := asn1.Unmarshal(item.der, &sequence); err != nil {
				t.Fatal(err)
			}
			contents := append(append([]byte(nil), sequence.Bytes...), 0x05, 0x00)
			malformed, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: contents})
			if err != nil {
				t.Fatal(err)
			}
			_, err = Match(testCertificate(t, item.key), malformed)
			if !errors.Is(err, ErrInvalidPrivateKey) {
				t.Fatalf("Match() error = %v, want ErrInvalidPrivateKey", err)
			}
		})
	}
}

func TestMatchRejectsPKCS8NestedExtraField(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := privateKeyFields(pkcs8DER)
	if err != nil {
		t.Fatal(err)
	}
	var nested asn1.RawValue
	if _, err := asn1.Unmarshal(outer[2].Bytes, &nested); err != nil {
		t.Fatal(err)
	}
	nestedExtra, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(append([]byte(nil), nested.Bytes...), 0x05, 0x00),
	})
	if err != nil {
		t.Fatal(err)
	}
	privateOctet, err := asn1.Marshal(nestedExtra)
	if err != nil {
		t.Fatal(err)
	}
	contents := append(append(append([]byte(nil), outer[0].FullBytes...), outer[1].FullBytes...), privateOctet...)
	malformed, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: contents})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Match(testCertificate(t, rsaKey), malformed)
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("Match() error = %v, want ErrInvalidPrivateKey", err)
	}
}

func TestMatchRejectsSEC1EmbeddedPublicMismatch(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := privateKeyFields(sec1)
	if err != nil {
		t.Fatal(err)
	}
	var publicIndex int = -1
	for index, field := range fields {
		if field.Class == asn1.ClassContextSpecific && field.Tag == 1 {
			publicIndex = index
		}
	}
	if publicIndex < 0 {
		t.Fatal("SEC1 fixture lacks an embedded public key")
	}
	var embedded asn1.BitString
	if _, err := asn1.Unmarshal(fields[publicIndex].Bytes, &embedded); err != nil {
		t.Fatal(err)
	}
	embedded.Bytes[len(embedded.Bytes)-1] ^= 0x01
	bitDER, err := asn1.Marshal(embedded)
	if err != nil {
		t.Fatal(err)
	}
	fields[publicIndex].Bytes = bitDER
	fields[publicIndex].FullBytes = nil
	var contents []byte
	for _, field := range fields {
		encoded, err := asn1.Marshal(field)
		if err != nil {
			t.Fatal(err)
		}
		contents = append(contents, encoded...)
	}
	malformed, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: contents})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Match(testCertificate(t, ecdsaKey), malformed)
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("Match() error = %v, want ErrInvalidPrivateKey", err)
	}
}

func TestMatchRejectsPKCS8ContradictoryECCurve(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := privateKeyFields(pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := privateKeyFields(outer[2].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	wrongCurveDER, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}) // P-384
	if err != nil {
		t.Fatal(err)
	}
	curveField, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: wrongCurveDER})
	if err != nil {
		t.Fatal(err)
	}
	innerContents := append(append(append([]byte(nil), inner[0].FullBytes...), inner[1].FullBytes...), curveField...)
	innerContents = append(innerContents, inner[2].FullBytes...)
	innerDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: innerContents})
	if err != nil {
		t.Fatal(err)
	}
	privateOctet, err := asn1.Marshal(innerDER)
	if err != nil {
		t.Fatal(err)
	}
	contents := append(append(append([]byte(nil), outer[0].FullBytes...), outer[1].FullBytes...), privateOctet...)
	malformed, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: contents})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Match(testCertificate(t, ecdsaKey), malformed)
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("Match() error = %v, want ErrInvalidPrivateKey", err)
	}
}

func TestDestroyPrivateKeyClearsSupportedValues(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey.Precompute()
	dp := rsaKey.Precomputed.Dp
	dq := rsaKey.Precomputed.Dq
	qinv := rsaKey.Precomputed.Qinv
	primes := append([]*big.Int(nil), rsaKey.Primes...)
	privateExponent := rsaKey.D
	destroyPrivateKey(rsaKey)
	if privateExponent.Sign() != 0 || rsaKey.Precomputed.Dp != nil {
		t.Fatal("RSA private exponent or precomputed values were retained")
	}
	for _, value := range append(primes, dp, dq, qinv) {
		if value != nil && value.Sign() != 0 {
			t.Fatal("RSA private component was not cleared")
		}
	}

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	destroyPrivateKey(ed25519Key)
	for _, value := range ed25519Key {
		if value != 0 {
			t.Fatal("Ed25519 private bytes were not cleared")
		}
	}
}

func FuzzMatch(f *testing.F) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	certificate := testCertificate(f, signer)
	validDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validDER)
	f.Add([]byte("not a key"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		result, err := Match(certificate, input)
		if err == nil && result.PrivateKeyEncoding == "" {
			t.Fatal("successful match omitted the private-key encoding")
		}
	})
}

func testCertificate(t testing.TB, signer crypto.Signer) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "match.rootwell.invalid"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
