package fileformat

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/publicbundle"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const keyPassword = "synthetic-file-format-password"

var (
	oidP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

type material struct {
	leaf, issuer []byte
	key          *ecdsa.PrivateKey
	sec1, pkcs8  []byte
}

func newMaterial(t testing.TB) material {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic Format CA"}, NotBefore: now, NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	issuer, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedIssuer, err := x509.ParseCertificate(issuer)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "format.test"}, DNSNames: []string{"format.test"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true}
	leaf, err := x509.CreateCertificate(rand.Reader, leafTemplate, parsedIssuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return material{leaf: leaf, issuer: issuer, key: key, sec1: sec1, pkcs8: pkcs8}
}

func block(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func p7b(t testing.TB, certificates ...[]byte) []byte {
	t.Helper()
	marshal := func(value any) []byte {
		out, err := asn1.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	raw := func(class, tag int, content ...[]byte) []byte {
		return marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: bytes.Join(content, nil)})
	}
	signed := raw(0, asn1.TagSequence, marshal(1), raw(0, asn1.TagSet), raw(0, asn1.TagSequence, marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})),
		raw(2, 0, certificates...), raw(0, asn1.TagSet))
	return raw(0, asn1.TagSequence, marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}), raw(2, 0, signed))
}

func oldStyle(t testing.TB, kind string, der []byte) []byte {
	t.Helper()
	//lint:ignore SA1019 Test fixture: the old format older OpenSSL wrote.
	encrypted, err := x509.EncryptPEMBlock(rand.Reader, kind, der, []byte(keyPassword), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(encrypted)
}

// certificatesAre checks that Certificates is strict PEM of exactly want.
func certificatesAre(t *testing.T, name string, parts Parts, want ...[]byte) {
	t.Helper()
	entries, err := publicbundle.Parse(parts.Certificates)
	if err != nil || len(entries) != len(want) || parts.Count != len(want) {
		t.Fatalf("%s: certificates are not strict PEM of %d: %v", name, len(want), err)
	}
	for i := range want {
		if !bytes.Equal(entries[i].DER, want[i]) {
			t.Fatalf("%s: certificate %d changed or moved", name, i)
		}
	}
}

func keyIs(t *testing.T, name string, parts Parts, key crypto.Signer) {
	t.Helper()
	err := keymatch.WithPrivateKey(parts.Key, func(parsed any, _ keymatch.Encoding) error {
		if !key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(parsed.(crypto.Signer).Public()) {
			return errors.New("another key")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%s: the key is not one strict key: %v", name, err)
	}
}

func TestSplitReadsWhatToolsWrite(t *testing.T) {
	m := newMaterial(t)
	leafPEM, issuerPEM := block("CERTIFICATE", m.leaf), block("CERTIFICATE", m.issuer)
	crlf := func(in []byte) []byte { return bytes.ReplaceAll(in, []byte("\n"), []byte("\r\n")) }
	bom := func(in []byte) []byte { return append([]byte{0xef, 0xbb, 0xbf}, in...) }
	bagAttributes := join([]byte("Bag Attributes\n    localKeyID: 5D D8 22 BE\n    friendlyName: format.test\nsubject=CN=format.test\nissuer=CN=Synthetic Format CA\n"), leafPEM,
		[]byte("Bag Attributes: <No Attributes>\nsubject=CN=Synthetic Format CA\nissuer=CN=Synthetic Format CA\n"), issuerPEM,
		[]byte("Bag Attributes\n    localKeyID: 5D D8 22 BE\n    friendlyName: Bak\xc4\xb1 server\nKey Attributes: <No Attributes>\n"), block("PRIVATE KEY", m.pkcs8))
	for name, test := range map[string]struct {
		input []byte
		certs [][]byte
		key   bool
	}{
		"one PEM certificate":          {leafPEM, [][]byte{m.leaf}, false},
		"one DER certificate":          {m.leaf, [][]byte{m.leaf}, false},
		"a chain":                      {join(leafPEM, issuerPEM), [][]byte{m.leaf, m.issuer}, false},
		"a byte order mark":            {bom(leafPEM), [][]byte{m.leaf}, false},
		"CRLF and a byte order mark":   {bom(crlf(join(leafPEM, issuerPEM))), [][]byte{m.leaf, m.issuer}, false},
		"a DER P7B":                    {p7b(t, m.leaf, m.issuer), [][]byte{m.leaf, m.issuer}, false},
		"a PEM P7B":                    {block("PKCS7", p7b(t, m.issuer, m.leaf)), [][]byte{m.issuer, m.leaf}, false},
		"an older P7B label":           {block("PKCS #7 SIGNED DATA", p7b(t, m.leaf)), [][]byte{m.leaf}, false},
		"HAProxy: cert, key, chain":    {join(leafPEM, block("PRIVATE KEY", m.pkcs8), issuerPEM), [][]byte{m.leaf, m.issuer}, true},
		"openssl pkcs12 -nodes output": {bagAttributes, [][]byte{m.leaf, m.issuer}, true},
		"text before a certificate":    {join([]byte("Certificate:\n    Data:\n        Version: 3 (0x2)\n"), leafPEM), [][]byte{m.leaf}, false},
	} {
		parts, err := Split(test.input)
		if err != nil || parts.PFX {
			t.Fatalf("%s: %v", name, err)
		}
		certificatesAre(t, name, parts, test.certs...)
		if test.key {
			keyIs(t, name, parts, m.key)
		} else if parts.Key != nil {
			t.Fatalf("%s: found a key that is not there", name)
		}
	}
	for name, input := range map[string][]byte{
		"EC PARAMETERS before SEC 1":   join(block("EC PARAMETERS", mustMarshal(t, oidP256)), block("EC PRIVATE KEY", m.sec1)),
		"EC PARAMETERS before PKCS#8":  join(block("EC PARAMETERS", mustMarshal(t, oidP256)), block("PRIVATE KEY", m.pkcs8)),
		"a DER key":                    m.pkcs8,
		"a key with a byte order mark": bom(crlf(block("EC PRIVATE KEY", m.sec1))),
	} {
		parts, err := Split(input)
		if err != nil || parts.Certificates != nil || parts.KeyLocked {
			t.Fatalf("%s: %v", name, err)
		}
		keyIs(t, name, parts, m.key)
	}
	locked, err := x509.MarshalPKCS8PrivateKey(m.key)
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := pkcs12.LegacyDES.Encode(m.key, mustParse(t, m.leaf), nil, keyPassword)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		input            []byte
		locked, oldStyle bool
	}{
		"an old-style encrypted key": {oldStyle(t, "EC PRIVATE KEY", m.sec1), true, true},
		"encrypted PKCS#8 PEM":       {block("ENCRYPTED PRIVATE KEY", encryptedPKCS8(t, locked)), true, false},
		"encrypted PKCS#8 DER":       {encryptedPKCS8(t, locked), true, false},
	} {
		parts, err := Split(test.input)
		if err != nil || parts.Key == nil || parts.KeyLocked != test.locked || parts.KeyOldStyle != test.oldStyle {
			t.Fatalf("%s: %+v %v", name, parts, err)
		}
	}
	for _, input := range [][]byte{pfx} {
		parts, err := Split(input)
		if err != nil || !parts.PFX || parts.Key != nil || parts.Certificates != nil {
			t.Fatalf("a PFX was not recognised by its content: %v", err)
		}
	}
}

func TestSplitRefusesAndNamesTheProblem(t *testing.T) {
	m := newMaterial(t)
	leafPEM := block("CERTIFICATE", m.leaf)
	keyPEM := block("PRIVATE KEY", m.pkcs8)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	brokenBase64 := []byte("-----BEGIN CERTIFICATE-----\nnot*base64!\n-----END CERTIFICATE-----\n")
	many := make([][]byte, 65)
	for i := range many {
		many[i] = leafPEM
	}
	signerP7B := bytes.Clone(p7b(t, m.leaf))
	signerP7B[len(signerP7B)-1] = 0x31 // a trailing SET header byte is no longer empty
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "format.test"}}, m.key)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		input []byte
		want  error
	}{
		"nothing":                    {nil, ErrEmpty},
		"only spaces":                {[]byte(" \r\n\t "), ErrEmpty},
		"only a byte order mark":     {[]byte{0xef, 0xbb, 0xbf}, ErrEmpty},
		"too large":                  {make([]byte, 16<<20+1), ErrTooLarge},
		"binary noise":               {[]byte{0x00, 0x01, 0x02, 0xff}, ErrUnreadable},
		"a mark before DER":          {append([]byte{0xef, 0xbb, 0xbf}, m.leaf...), ErrUnreadable},
		"plain words":                {[]byte("hello, this is not a certificate\n"), ErrUnreadable},
		"a control character":        {join([]byte("Bag Attributes\x07\n"), leafPEM), ErrUnreadable},
		"a stray END line":           {join(leafPEM, []byte("-----END CERTIFICATE-----\n")), ErrUnreadable},
		"a BEGIN without an END":     {[]byte("-----BEGIN CERTIFICATE-----\nMIIB\n"), ErrUnreadable},
		"broken base64, then good":   {join(brokenBase64, leafPEM), ErrUnreadable},
		"an END of another kind":     {[]byte(strings.Replace(string(leafPEM), "END CERTIFICATE", "END PRIVATE KEY", 1)), ErrUnreadable},
		"two keys":                   {join(keyPEM, block("EC PRIVATE KEY", m.sec1)), ErrSeveralKeys},
		"a certificate request":      {block("CERTIFICATE REQUEST", csr), ErrCertificateRequest},
		"a public key":               {block("PUBLIC KEY", []byte{0x30, 0x00}), ErrUnknownBlock},
		"a revocation list":          {join(leafPEM, block("X509 CRL", []byte{0x30, 0x00})), ErrUnknownBlock},
		"an OpenSSL trusted cert":    {block("TRUSTED CERTIFICATE", m.leaf), ErrUnknownBlock},
		"a damaged certificate":      {block("CERTIFICATE", m.leaf[:len(m.leaf)-1]), ErrBadCertificate},
		"a certificate with headers": {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Note": "x"}, Bytes: m.leaf}), ErrUnknownBlock},
		"a key with other headers":   {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Note": "x"}, Bytes: m.pkcs8}), ErrUnknownBlock},
		"a P7B with a signer":        {signerP7B, ErrPKCS7},
		"a P7B block with a signer":  {block("PKCS7", signerP7B), ErrPKCS7},
		"65 certificates":            {join(many...), ErrTooManyCertificates},
		"EC parameters alone":        {block("EC PARAMETERS", mustMarshal(t, oidP256)), ErrKeyParameters},
		"EC parameters, RSA key":     {join(block("EC PARAMETERS", mustMarshal(t, oidP256)), block("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))), ErrKeyParameters},
		"EC parameters, other curve": {join(block("EC PARAMETERS", mustMarshal(t, oidP384)), block("EC PRIVATE KEY", m.sec1)), ErrKeyParameters},
		"explicit EC parameters":     {join(block("EC PARAMETERS", []byte{0x30, 0x03, 0x02, 0x01, 0x01}), block("EC PRIVATE KEY", m.sec1)), ErrKeyParameters},
		"EC parameters twice":        {join(block("EC PARAMETERS", mustMarshal(t, oidP256)), block("EC PARAMETERS", mustMarshal(t, oidP256)), block("EC PRIVATE KEY", m.sec1)), ErrKeyParameters},
	} {
		parts, err := Split(test.input)
		if !errors.Is(err, test.want) || parts.Key != nil || parts.Certificates != nil || parts.PFX {
			t.Fatalf("%s: got %v, want %v", name, err, test.want)
		}
	}
}

func TestUnlockOpensOldStyleKeys(t *testing.T) {
	m := newMaterial(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		der  []byte
		kind string
		key  crypto.Signer
	}{
		"EC":  {m.sec1, "EC PRIVATE KEY", m.key},
		"RSA": {x509.MarshalPKCS1PrivateKey(rsaKey), "RSA PRIVATE KEY", rsaKey},
	} {
		parts, err := Split(oldStyle(t, test.kind, test.der))
		if err != nil || !parts.KeyOldStyle {
			t.Fatalf("%s: %v", name, err)
		}
		opened, err := Unlock(parts.Key, []byte(keyPassword))
		if err != nil || !bytes.HasPrefix(opened, []byte("-----BEGIN "+test.kind+"-----\n")) || bytes.Contains(opened, []byte("Proc-Type")) {
			t.Fatalf("%s: %v", name, err)
		}
		keyIs(t, name, Parts{Key: opened}, test.key)
		if _, err := Unlock(parts.Key, []byte("not-"+keyPassword)); !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("%s: a wrong password gave %v", name, err)
		}
		if _, err := Unlock(parts.Key, nil); !errors.Is(err, ErrPasswordRequired) {
			t.Fatalf("%s: no password gave %v", name, err)
		}
	}
	if _, err := Unlock(block("EC PRIVATE KEY", m.sec1), []byte(keyPassword)); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("an unlocked key went through Unlock: %v", err)
	}
}

func TestKeyPreparesKeyFilesForTheStrictReaders(t *testing.T) {
	m := newMaterial(t)
	leafPEM := block("CERTIFICATE", m.leaf)
	encrypted := block("ENCRYPTED PRIVATE KEY", encryptedPKCS8(t, m.pkcs8))
	for name, test := range map[string]struct {
		input, password []byte
		samePassword    bool
	}{
		"EC PARAMETERS first":  {join(block("EC PARAMETERS", mustMarshal(t, oidP256)), block("EC PRIVATE KEY", m.sec1)), nil, true},
		"a combined file":      {join(leafPEM, block("PRIVATE KEY", m.pkcs8)), nil, true},
		"an old-style key":     {oldStyle(t, "EC PRIVATE KEY", m.sec1), []byte(keyPassword), false},
		"encrypted PKCS#8 PEM": {encrypted, []byte(keyPassword), true},
	} {
		key, password, err := Key(test.input, test.password)
		if err != nil || bytes.Equal(key, test.input) && name != "encrypted PKCS#8 PEM" {
			t.Fatalf("%s: %v", name, err)
		}
		if test.samePassword != bytes.Equal(password, test.password) || (!test.samePassword && password != nil) {
			t.Fatalf("%s: wrong password handed on", name)
		}
		if name != "encrypted PKCS#8 PEM" {
			keyIs(t, name, Parts{Key: key}, m.key)
		}
	}
	if _, _, err := Key(oldStyle(t, "EC PRIVATE KEY", m.sec1), nil); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("an old-style key without a password gave %v", err)
	}
	if _, _, err := Key(oldStyle(t, "EC PRIVATE KEY", m.sec1), []byte("wrong")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("an old-style key with a wrong password gave %v", err)
	}
	for _, other := range [][]byte{leafPEM, []byte("not a key"), m.leaf} {
		if key, password, err := Key(other, []byte("x")); err != nil || !bytes.Equal(key, other) || string(password) != "x" {
			t.Fatal("a file without a key did not go back unchanged")
		}
	}
}

func mustMarshal(t testing.TB, value any) []byte {
	t.Helper()
	out, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustParse(t testing.TB, der []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

// encryptedPKCS8 is a shape-only EncryptedPrivateKeyInfo: Split never
// decrypts it, the strict key reader does.
func encryptedPKCS8(t testing.TB, plain []byte) []byte {
	return mustMarshal(t, struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}}, plain[:16]})
}

func FuzzSplit(f *testing.F) {
	m := newMaterial(f)
	f.Add(join(block("CERTIFICATE", m.leaf), block("PRIVATE KEY", m.pkcs8)))
	f.Add(join([]byte("Bag Attributes\n    friendlyName: x\n"), block("CERTIFICATE", m.leaf)))
	f.Add(join(block("EC PARAMETERS", mustMarshal(f, oidP256)), block("EC PRIVATE KEY", m.sec1)))
	f.Add(block("PKCS7", p7b(f, m.leaf, m.issuer)))
	f.Add(oldStyle(f, "EC PRIVATE KEY", m.sec1))
	f.Add(m.leaf)
	f.Fuzz(func(t *testing.T, input []byte) {
		parts, err := Split(input)
		if err != nil {
			if parts.Key != nil || parts.Certificates != nil || parts.PFX {
				t.Fatal("a refusal returned parts")
			}
			return
		}
		if parts.PFX && (parts.Key != nil || parts.Certificates != nil) {
			t.Fatal("a PFX came back with other parts")
		}
		if parts.Certificates != nil {
			entries, err := publicbundle.Parse(parts.Certificates)
			if err != nil && !errors.Is(err, publicbundle.ErrDuplicateCertificate) {
				t.Fatalf("certificates are not strict PEM: %v", err)
			}
			if err == nil && len(entries) != parts.Count {
				t.Fatal("the count is wrong")
			}
		}
		if parts.Key != nil && bytes.HasPrefix(parts.Key, []byte("-----BEGIN ")) {
			decoded, rest := pem.Decode(parts.Key)
			if decoded == nil || len(rest) != 0 || (len(decoded.Headers) != 0) != parts.KeyOldStyle {
				t.Fatal("the key is not one block")
			}
		}
		if !parts.PFX && parts.Key == nil && parts.Certificates == nil {
			t.Fatal("success with nothing in it")
		}
		_, _, _ = Key(input, []byte(keyPassword))
	})
}
