package pkcs7certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

func certificates(t testing.TB, count int) [][]byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	out := make([][]byte, count)
	for i := range out {
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "p7b-" + string(rune('a'+i%26))},
			NotBefore: now, NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true}
		out[i], err = x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func raw(t testing.TB, class, tag int, content ...[]byte) []byte {
	t.Helper()
	out, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: bytes.Join(content, nil)})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func marshal(t testing.TB, value any) []byte {
	t.Helper()
	out, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// p7b is one certs-only bundle with parts a test may change.
type p7b struct {
	contentType asn1.ObjectIdentifier
	version     int
	digests     []byte // inside the digestAlgorithms SET
	content     []byte // after the data OID
	certs       [][]byte
	noCerts     bool
	crls        []byte // nil: absent
	signers     []byte // inside the signerInfos SET
}

func (b p7b) build(t testing.TB) []byte {
	t.Helper()
	if b.contentType == nil {
		b.contentType = oidSignedData
	}
	if b.version == 0 {
		b.version = 1
	}
	fields := [][]byte{marshal(t, b.version), raw(t, asn1.ClassUniversal, asn1.TagSet, b.digests),
		raw(t, asn1.ClassUniversal, asn1.TagSequence, marshal(t, oidData), b.content)}
	if !b.noCerts {
		fields = append(fields, raw(t, asn1.ClassContextSpecific, 0, b.certs...))
	}
	if b.crls != nil {
		fields = append(fields, raw(t, asn1.ClassContextSpecific, 1, b.crls))
	}
	fields = append(fields, raw(t, asn1.ClassUniversal, asn1.TagSet, b.signers))
	signed := raw(t, asn1.ClassUniversal, asn1.TagSequence, fields...)
	return raw(t, asn1.ClassUniversal, asn1.TagSequence, marshal(t, b.contentType), raw(t, asn1.ClassContextSpecific, 0, signed))
}

func TestParseReadsCertsOnlyBundles(t *testing.T) {
	certs := certificates(t, 3)
	for name, bundle := range map[string]p7b{
		"one":           {certs: certs[:1]},
		"three":         {certs: certs},
		"empty CRL set": {certs: certs, crls: []byte{}},
	} {
		got, err := Parse(bundle.build(t))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != len(bundle.certs) {
			t.Fatalf("%s: %d certificates, want %d", name, len(got), len(bundle.certs))
		}
		for i := range got {
			if !bytes.Equal(got[i], bundle.certs[i]) {
				t.Fatalf("%s: certificate %d changed or moved", name, i)
			}
		}
	}
}

func TestParseRefusesWhatItDoesNotUnderstand(t *testing.T) {
	certs := certificates(t, 2)
	many := certificates(t, 65)
	sha256ID := marshal(t, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}})
	good := p7b{certs: certs}.build(t)
	header := 2
	if good[1] > 0x80 {
		header += int(good[1] & 0x7f)
	}
	ber := append([]byte{0x30, 0x80}, good[header:]...)
	ber = append(ber, 0x00, 0x00)
	for name, input := range map[string][]byte{
		"a signer":              p7b{certs: certs, signers: raw(t, asn1.ClassUniversal, asn1.TagSequence, marshal(t, 1))}.build(t),
		"a digest algorithm":    p7b{certs: certs, digests: sha256ID}.build(t),
		"signed content":        p7b{certs: certs, content: raw(t, asn1.ClassContextSpecific, 0, marshal(t, []byte("hello")))}.build(t),
		"a revocation list":     p7b{certs: certs, crls: raw(t, asn1.ClassUniversal, asn1.TagSequence, marshal(t, 1))}.build(t),
		"an attribute cert":     p7b{certs: [][]byte{certs[0], raw(t, asn1.ClassContextSpecific, 1, marshal(t, 1))}}.build(t),
		"version 3":             p7b{certs: certs, version: 3}.build(t),
		"no certificates":       p7b{noCerts: true}.build(t),
		"an empty set":          p7b{}.build(t),
		"65 certificates":       p7b{certs: many}.build(t),
		"a duplicate":           p7b{certs: [][]byte{certs[0], certs[0]}}.build(t),
		"a damaged certificate": p7b{certs: [][]byte{raw(t, asn1.ClassUniversal, asn1.TagSequence, marshal(t, 1))}}.build(t),
		"trailing bytes":        append(bytes.Clone(good), 0),
		"BER lengths":           ber,
	} {
		if _, err := Parse(input); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s: got %v, want a refusal", name, err)
		}
		if !IsPKCS7(input) {
			t.Fatalf("%s: no longer recognised as PKCS#7", name)
		}
	}
	for name, input := range map[string][]byte{
		"a certificate":   certs[0],
		"enveloped data":  p7b{certs: certs, contentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}}.build(t),
		"text":            []byte("-----BEGIN PKCS7-----"),
		"empty":           nil,
		"a short header":  {0x30},
		"a long sequence": {0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
	} {
		if _, err := Parse(input); !errors.Is(err, ErrNotPKCS7) {
			t.Fatalf("%s: got %v, want not PKCS#7", name, err)
		}
	}
}

func FuzzParseCertsOnly(f *testing.F) {
	certs := certificates(f, 2)
	f.Add(p7b{certs: certs}.build(f))
	f.Add(p7b{certs: certs, crls: []byte{}}.build(f))
	f.Add([]byte{0x30, 0x80})
	f.Fuzz(func(t *testing.T, input []byte) {
		got, err := Parse(input)
		if err != nil {
			if !errors.Is(err, ErrNotPKCS7) && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unexpected refusal: %v", err)
			}
			return
		}
		if len(got) == 0 || len(got) > 64 || !IsPKCS7(input) {
			t.Fatal("accepted an empty, oversized or unrecognised bundle")
		}
		for _, der := range got {
			if _, err := x509.ParseCertificate(der); err != nil {
				t.Fatal("returned something that is not a certificate")
			}
			if !bytes.Contains(input, der) {
				t.Fatal("returned bytes that are not in the input")
			}
		}
	})
}
