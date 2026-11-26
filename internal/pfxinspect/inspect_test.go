package pfxinspect

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
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/pfxfixture"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const testPassword = "R00twell-Inspect-fixture-93f2"

func fixture(t *testing.T) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(87), Subject: pkix.Name{CommonName: "pfx-inspect.example"}, DNSNames: []string{"pfx-inspect.example"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pkcs12.Modern2023.WithIterations(100_000).Encode(key, certificate, nil, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return data, certificate, key
}

// chain is a leaf, its key and its issuing CA, for layouts with two
// certificates in which the CA may come first.
type chain struct {
	leaf, issuer *x509.Certificate
	key          crypto.Signer
}

func newChain(t testing.TB, rsaLeaf bool) chain {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var leafKey crypto.Signer
	if rsaLeaf {
		leafKey, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(90), Subject: pkix.Name{CommonName: "Synthetic PFX Issuing CA"}, NotBefore: now, NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(91), Subject: pkix.Name{CommonName: "pfx-layout.test"}, DNSNames: []string{"pfx-layout.test"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, leafKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return chain{leaf: leaf, issuer: issuer, key: leafKey}
}

func expectOpens(t *testing.T, name string, data []byte, password string, c chain) {
	t.Helper()
	result, err := Inspect(data, password)
	if err != nil {
		t.Fatalf("%s: %v (code %q)", name, err, Code(err))
	}
	if result.MatchingCertificate.Subject != c.leaf.Subject.String() || len(result.Additional) != 1 || result.Additional[0].Subject != c.issuer.Subject.String() {
		t.Fatalf("%s: wrong public result: %+v", name, result)
	}
	err = Open(data, password, func(opened Result, key crypto.Signer) error {
		if !c.key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()) {
			t.Fatalf("%s: Open lent another key", name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%s: Open: %v", name, err)
	}
}

func TestBuilderAgreesWithPinnedDecoder(t *testing.T) {
	c := newChain(t, false)
	for name, data := range map[string][]byte{
		"modern": pfxfixture.OpenSSL(t, c.leaf, c.issuer, c.key, testPassword, pfxfixture.Modern(), oidSHA256).Build(t),
		"3DES":   pfxfixture.Windows(t, c.leaf, c.issuer, c.key, testPassword).Build(t),
	} {
		key, leaf, others, err := pkcs12.DecodeChain(data, testPassword)
		if err != nil || key == nil || leaf == nil || len(others) != 1 {
			t.Fatalf("%s fixture is not a PFX the pinned decoder reads: %v", name, err)
		}
	}
}

func TestInspectModernPFXPublicOnly(t *testing.T) {
	data, certificate, _ := fixture(t)
	result, err := Inspect(data, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if result.MatchingCertificate.Subject != certificate.Subject.String() || len(result.Additional) != 0 {
		t.Fatalf("wrong public result: %+v", result)
	}
	if bytes.Contains([]byte(result.MatchingCertificate.Subject), []byte(testPassword)) {
		t.Fatal("password leaked into public result")
	}
}

func TestCertificateDERSelectsExactPublicObject(t *testing.T) {
	data, certificate, _ := fixture(t)
	result, err := Inspect(data, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := result.CertificateDER(result.MatchingCertificate.SHA256Fingerprint)
	if !ok || !bytes.Equal(got, certificate.Raw) {
		t.Fatal("selected certificate DER changed")
	}
	got[0] ^= 0xff
	again, ok := result.CertificateDER(result.MatchingCertificate.SHA256Fingerprint)
	if !ok || !bytes.Equal(again, certificate.Raw) {
		t.Fatal("caller changed retained public certificate")
	}
	other := result.MatchingCertificate.SHA256Fingerprint[:94] + "0"
	if other == result.MatchingCertificate.SHA256Fingerprint {
		other = result.MatchingCertificate.SHA256Fingerprint[:94] + "1"
	}
	for _, fingerprint := range []string{other, "", "lowercase", result.MatchingCertificate.SHA256Fingerprint + ":00"} {
		if der, ok := result.CertificateDER(fingerprint); ok || der != nil {
			t.Fatal("unknown or malformed fingerprint selected a certificate")
		}
	}
}

func TestInspectRejectsWrongPasswordTamperAndUnsupported(t *testing.T) {
	data, _, _ := fixture(t)
	for _, password := range []string{"wrong-password", "", testPassword + " "} {
		if _, err := Inspect(data, password); !errors.Is(err, ErrWrongPassword) || Code(err) != "wrong-password" {
			t.Fatalf("wrong password %q was not named as one: %v", password, err)
		}
	}
	tampered := bytes.Clone(data)
	tampered[len(tampered)-8] ^= 0x01
	if _, err := Inspect(tampered, testPassword); err == nil {
		t.Fatal("tampered PFX accepted")
	}
	for _, input := range [][]byte{nil, data[:len(data)-1], append(bytes.Clone(data), 0), bytes.Repeat([]byte{0}, maxInputBytes+1)} {
		if _, err := Inspect(input, testPassword); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("malformed or oversized PFX accepted: %v", err)
		}
	}
	for _, password := range []string{"tab\tinside", "newline\n", string([]byte{0xff, 0xfe}), string(bytes.Repeat([]byte("a"), 129))} {
		if _, err := Inspect(data, password); err == nil || errors.Is(err, ErrWrongPassword) {
			t.Fatalf("unusable password %q reached the decoder: %v", password, err)
		}
	}
}

func TestPreflightRejectsExcessiveKDFBeforeDecode(t *testing.T) {
	data, _, _ := fixture(t)
	current, err := asn1.Marshal(100_000)
	if err != nil {
		t.Fatal(err)
	}
	excessive, err := asn1.Marshal(250_001)
	if err != nil || len(current) != len(excessive) {
		t.Fatal("test integer encoding changed")
	}
	if count := bytes.Count(data, current); count != 3 {
		t.Fatalf("expected three visible KDF work factors, got %d", count)
	}
	for position := 0; position < len(data); {
		relative := bytes.Index(data[position:], current)
		if relative < 0 {
			break
		}
		position += relative
		mutated := bytes.Clone(data)
		copy(mutated[position:position+len(current)], excessive)
		if err := Preflight(mutated); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("excessive KDF at offset %d accepted: %v", position, err)
		}
		if _, err := Inspect(mutated, testPassword); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("excessive KDF at offset %d reached decoder: %v", position, err)
		}
		position += len(current)
	}
}

func TestInspectRejectsMismatchedKeyAndDuplicateCertificate(t *testing.T) {
	_, certificate, key := fixture(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mismatched, err := pkcs12.Modern2023.WithIterations(100_000).Encode(otherKey, certificate, nil, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(mismatched, testPassword); !errors.Is(err, ErrInvalid) || Code(err) != "contents" {
		t.Fatalf("mismatched key accepted: %v", err)
	}
	duplicate, err := pkcs12.Modern2023.WithIterations(100_000).Encode(key, certificate, []*x509.Certificate{certificate}, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(duplicate, testPassword); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate certificate accepted: %v", err)
	}
}

func TestInspectShowsAdditionalCertificateWithoutTrustClaim(t *testing.T) {
	_, certificate, key := fixture(t)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(88), Subject: pkix.Name{CommonName: "unverified-issuer.example"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, template, template, issuerKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pkcs12.Modern2023.WithIterations(100_000).Encode(key, certificate, []*x509.Certificate{issuer}, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Inspect(data, testPassword)
	if err != nil || len(result.Additional) != 1 || result.Additional[0].Subject != issuer.Subject.String() {
		t.Fatalf("additional certificate missing: %+v, %v", result, err)
	}
	selected, ok := result.CertificateDER(result.Additional[0].SHA256Fingerprint)
	if !ok || !bytes.Equal(selected, issuer.Raw) {
		t.Fatal("additional public certificate could not be selected")
	}
}

// Windows, .NET, OpenSSL -legacy, OpenSSL 3 and Java keytool write these
// protections; each opens with its password and with nothing else.
func TestInspectOpensProducerProfiles(t *testing.T) {
	c := newChain(t, false)
	cases := map[string][]byte{}
	for name, encoder := range map[string]*pkcs12.Encoder{"OpenSSL -legacy RC2": pkcs12.LegacyRC2, "3DES": pkcs12.LegacyDES, "OpenSSL 3": pkcs12.Modern2023} {
		data, err := encoder.Encode(c.key, c.leaf, []*x509.Certificate{c.issuer}, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		cases[name] = data
	}
	cases["Windows 3DES, CA first"] = pfxfixture.Windows(t, c.leaf, c.issuer, c.key, testPassword).Build(t)
	aes128 := pfxfixture.Protection{AESKey: 16, PRF: oidHMACSHA1, Iterations: 2048, SaltBytes: 8, IVBytes: 16}
	cases["AES-128, HMAC-SHA-1, SHA-1 MAC"] = pfxfixture.OpenSSL(t, c.leaf, c.issuer, c.key, testPassword, aes128, oidSHA1).Build(t)
	aes192 := pfxfixture.Protection{AESKey: 24, KeyLength: 24, Iterations: 2048, SaltBytes: 8, IVBytes: 16}
	cases["AES-192, default PRF"] = pfxfixture.OpenSSL(t, c.leaf, c.issuer, c.key, testPassword, aes192, oidSHA256).Build(t)
	aes256 := pfxfixture.Protection{AESKey: 32, PRF: oidHMACSHA512, PRFParams: []byte{}, Iterations: 4096, SaltBytes: 32, IVBytes: 16}
	cases["AES-256, HMAC-SHA-512, SHA-512 MAC"] = pfxfixture.OpenSSL(t, c.leaf, c.issuer, c.key, testPassword, aes256, oidSHA512).Build(t)
	java := pfxfixture.Modern()
	java.Iterations, java.SaltBytes = 10_000, 20
	javaSpec := pfxfixture.OpenSSL(t, c.leaf, c.issuer, c.key, testPassword, java, oidSHA256)
	javaSpec.MACIterations = 100_000
	cases["Java keytool"] = javaSpec.Build(t)
	for name, data := range cases {
		if err := Preflight(data); err != nil {
			t.Fatalf("%s refused before the password: %v", name, err)
		}
		expectOpens(t, name, data, testPassword, c)
		if _, err := Inspect(data, "not-"+testPassword); Code(err) != "wrong-password" {
			t.Fatalf("%s: a wrong password was not named as one: %v", name, err)
		}
	}
	rsaChain := newChain(t, true)
	expectOpens(t, "Windows RSA", pfxfixture.Windows(t, rsaChain.leaf, rsaChain.issuer, rsaChain.key, testPassword).Build(t), testPassword, rsaChain)
}

// An empty password is either an empty BMPString or no password bytes at
// all; both open with an empty password and with no other.
func TestInspectOpensEmptyPasswordBothWays(t *testing.T) {
	c := newChain(t, false)
	cases := map[string][]byte{}
	for name, encoder := range map[string]*pkcs12.Encoder{"modern": pkcs12.Modern2023, "3DES": pkcs12.LegacyDES} {
		data, err := encoder.Encode(c.key, c.leaf, []*x509.Certificate{c.issuer}, "")
		if err != nil {
			t.Fatal(err)
		}
		cases["empty BMPString, "+name] = data
	}
	absent3DES := pfxfixture.Spec{AbsentPassword: true, MACDigest: oidSHA1}
	des := pfxfixture.DES()
	absent3DES.Safes = []pfxfixture.Safe{
		{Bags: []pfxfixture.Bag{absent3DES.KeyBag(t, c.key, des)}},
		{Encrypted: &des, Bags: []pfxfixture.Bag{pfxfixture.CertificateBag(t, c.issuer.Raw), pfxfixture.CertificateBag(t, c.leaf.Raw)}},
	}
	cases["no password bytes, 3DES"] = absent3DES.Build(t)
	absentModern := pfxfixture.Spec{AbsentPassword: true}
	modern := pfxfixture.Modern()
	absentModern.Safes = []pfxfixture.Safe{
		{Encrypted: &modern, Bags: []pfxfixture.Bag{pfxfixture.CertificateBag(t, c.leaf.Raw), pfxfixture.CertificateBag(t, c.issuer.Raw)}},
		{Bags: []pfxfixture.Bag{absentModern.KeyBag(t, c.key, modern)}},
	}
	cases["no password bytes, AES"] = absentModern.Build(t)
	for name, data := range cases {
		expectOpens(t, name, data, "", c)
		if _, err := Inspect(data, "x"); Code(err) != "wrong-password" {
			t.Fatalf("%s opened with a password it does not have: %v", name, err)
		}
	}
}

// Windows labels a machine key and, with extended properties, each
// certificate with attributes the strict lister cannot name. Such a PFX still
// opens, and still holds exactly one key.
func TestInspectWindowsAttributesStillOpen(t *testing.T) {
	c := newChain(t, false)
	machine := pfxfixture.Windows(t, c.leaf, c.issuer, c.key, testPassword, pfxfixture.LocalKeyID(t), pfxfixture.Attr(pfxfixture.OIDMachineKeySet))
	expectOpens(t, "machine key set", machine.Build(t), testPassword, c)

	extended := pfxfixture.Windows(t, c.leaf, c.issuer, c.key, testPassword)
	des := pfxfixture.DES()
	property := pfxfixture.Attr(pfxfixture.OIDExtendedProperty, pfxfixture.Marshal(t, []byte("synthetic property")))
	extended.Safes[1] = pfxfixture.Safe{Encrypted: &des, Bags: []pfxfixture.Bag{pfxfixture.CertificateBag(t, c.issuer.Raw, property), pfxfixture.CertificateBag(t, c.leaf.Raw, pfxfixture.LocalKeyID(t), property)}}
	expectOpens(t, "extended properties", extended.Build(t), testPassword, c)

	second := newChain(t, false)
	hidden := pfxfixture.Windows(t, c.leaf, c.issuer, c.key, testPassword, pfxfixture.LocalKeyID(t), pfxfixture.Attr(pfxfixture.OIDMachineKeySet))
	hidden.Safes[1] = pfxfixture.Safe{Encrypted: &des, Bags: []pfxfixture.Bag{pfxfixture.CertificateBag(t, c.issuer.Raw), pfxfixture.CertificateBag(t, c.leaf.Raw), hidden.KeyBag(t, second.key, des)}}
	if _, err := Inspect(hidden.Build(t), testPassword); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a second key hidden in the encrypted safe was accepted: %v", err)
	}
}

// Inside an encrypted safe nothing is visible before the password. Once the
// MAC verifies, every bag there must still be a certificate.
func TestInspectRefusesUnknownBagInEncryptedSafe(t *testing.T) {
	c := newChain(t, false)
	second := newChain(t, false)
	modern := pfxfixture.Modern()
	for name, extra := range map[string]func(spec pfxfixture.Spec) pfxfixture.Bag{
		"secret bag":   func(pfxfixture.Spec) pfxfixture.Bag { return pfxfixture.OtherBag(t, pfxfixture.OIDSecretBag) },
		"CRL bag":      func(pfxfixture.Spec) pfxfixture.Bag { return pfxfixture.OtherBag(t, pfxfixture.OIDCRLBag) },
		"nested safe":  func(pfxfixture.Spec) pfxfixture.Bag { return pfxfixture.OtherBag(t, pfxfixture.OIDNestedSafe) },
		"unknown bag":  func(pfxfixture.Spec) pfxfixture.Bag { return pfxfixture.OtherBag(t, asn1.ObjectIdentifier{1, 2, 3, 4}) },
		"a second key": func(spec pfxfixture.Spec) pfxfixture.Bag { return spec.KeyBag(t, second.key, modern) },
	} {
		spec := pfxfixture.OpenSSL(t, c.leaf, c.issuer, c.key, testPassword, modern, oidSHA256)
		spec.Safes[0].Bags = append(spec.Safes[0].Bags, extra(spec))
		data := spec.Build(t)
		if err := Preflight(data); err != nil {
			t.Fatalf("%s: the visible layout should pass: %v", name, err)
		}
		if _, err := Inspect(data, testPassword); !errors.Is(err, ErrInvalid) || Code(err) != "contents" {
			t.Fatalf("%s inside the encrypted safe was accepted: %v", name, err)
		}
	}
}

func TestPreflightRefusesUnsupportedLayoutsBeforePassword(t *testing.T) {
	c := newChain(t, false)
	modern := pfxfixture.Modern()
	build := func(change func(*pfxfixture.Spec)) []byte {
		spec := pfxfixture.OpenSSL(t, c.leaf, c.issuer, c.key, testPassword, modern, oidSHA256)
		change(&spec)
		return spec.Build(t)
	}
	withProtection := func(change func(*pfxfixture.Protection)) []byte {
		p := pfxfixture.Modern()
		change(&p)
		return pfxfixture.OpenSSL(t, c.leaf, c.issuer, c.key, testPassword, p, oidSHA256).Build(t)
	}
	key := func(spec *pfxfixture.Spec) pfxfixture.Bag { return spec.KeyBag(t, c.key, modern) }
	pbmac1, err := pkcs12.Modern2026.Encode(c.key, c.leaf, nil, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	signed := build(func(*pfxfixture.Spec) {})
	envelope := pfxEnvelope{}
	if _, err := asn1.Unmarshal(signed, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.AuthSafe.ContentType = oidSignedData
	signedData := pfxfixture.Marshal(t, envelope)
	envelope.AuthSafe.ContentType, envelope.Version = oidData, 2
	versionTwo := pfxfixture.Marshal(t, envelope)
	cases := map[string]struct {
		data []byte
		code string
	}{
		"SHA-384 MAC":         {build(func(s *pfxfixture.Spec) { s.MACDigest = pfxfixture.OIDSHA384 }), "unsupported"},
		"PBMAC1":              {pbmac1, "unsupported"},
		"no MAC":              {build(func(s *pfxfixture.Spec) { s.NoMAC = true }), "no-integrity"},
		"MAC over 250000":     {build(func(s *pfxfixture.Spec) { s.MACIterations = 250_001 }), "unsupported"},
		"HMAC-SHA-384 PRF":    {withProtection(func(p *pfxfixture.Protection) { p.PRF = pfxfixture.OIDHMACSHA384 }), "unsupported"},
		"PRF parameters":      {withProtection(func(p *pfxfixture.Protection) { p.PRFParams = []byte{0x02, 0x01, 0x00} }), "unsupported"},
		"key length mismatch": {withProtection(func(p *pfxfixture.Protection) { p.KeyLength = 16 }), "unsupported"},
		"short salt":          {withProtection(func(p *pfxfixture.Protection) { p.SaltBytes = 7 }), "unsupported"},
		"short IV":            {withProtection(func(p *pfxfixture.Protection) { p.IVBytes = 8 }), "unsupported"},
		"partial block":       {withProtection(func(p *pfxfixture.Protection) { p.TrimCipher = true }), "unsupported"},
		"3DES over 250000":    {withProtection(func(p *pfxfixture.Protection) { *p = pfxfixture.DES(); p.Iterations = 250_001 }), "unsupported"},
		"one safe":            {build(func(s *pfxfixture.Spec) { s.Safes = s.Safes[1:] }), "unsupported"},
		"three safes": {build(func(s *pfxfixture.Spec) {
			s.Safes = append(s.Safes, pfxfixture.Safe{Bags: []pfxfixture.Bag{pfxfixture.CertificateBag(t, c.issuer.Raw)}})
		}), "unsupported"},
		"key safe encrypted": {build(func(s *pfxfixture.Spec) { s.Safes[1].Encrypted = &modern }), "unsupported"},
		"plain key bag":      {build(func(s *pfxfixture.Spec) { s.Safes[1].Bags[0].ID = pfxfixture.OIDKeyBag }), "unsupported"},
		"two visible keys":   {build(func(s *pfxfixture.Spec) { s.Safes[1].Bags = append(s.Safes[1].Bags, key(s)) }), "unsupported"},
		"no key": {build(func(s *pfxfixture.Spec) {
			s.Safes[1].Bags = []pfxfixture.Bag{pfxfixture.CertificateBag(t, c.issuer.Raw)}
		}), "unsupported"},
		"visible CRL bag": {build(func(s *pfxfixture.Spec) {
			s.Safes[1].Bags = append(s.Safes[1].Bags, pfxfixture.OtherBag(t, pfxfixture.OIDCRLBag))
		}), "unsupported"},
		"visible secret bag": {build(func(s *pfxfixture.Spec) {
			s.Safes[1].Bags = append(s.Safes[1].Bags, pfxfixture.OtherBag(t, pfxfixture.OIDSecretBag))
		}), "unsupported"},
		"visible nested safe": {build(func(s *pfxfixture.Spec) {
			s.Safes[1].Bags = append(s.Safes[1].Bags, pfxfixture.OtherBag(t, pfxfixture.OIDNestedSafe))
		}), "unsupported"},
		"other certificate": {build(func(s *pfxfixture.Spec) {
			s.Safes[1].Bags[0] = func() pfxfixture.Bag {
				b := pfxfixture.CertificateBag(t, c.issuer.Raw)
				b.Value = pfxfixture.Explicit(pfxfixture.Marshal(t, certBag{ID: pfxfixture.OIDSDSICert, Data: []byte("x")}))
				return b
			}()
		}), "unsupported"},
		"too many bags": {build(func(s *pfxfixture.Spec) {
			s.Safes[1].Bags = append(s.Safes[1].Bags, bytesOf(17, pfxfixture.CertificateBag(t, c.issuer.Raw))...)
		}), "unsupported"},
		"too many attributes":  {build(func(s *pfxfixture.Spec) { s.Safes[1].Bags[0].Attributes = attributesOf(9, pfxfixture.LocalKeyID(t)) }), "unsupported"},
		"public-key integrity": {signedData, "unsupported"},
		"version 2":            {versionTwo, "not-pfx"},
		"not a PFX":            {[]byte("-----BEGIN CERTIFICATE-----\n"), "not-pfx"},
		"empty":                {nil, "not-pfx"},
	}
	for name, test := range cases {
		err := Preflight(test.data)
		if !errors.Is(err, ErrUnsupported) || Code(err) != test.code {
			t.Fatalf("%s: preflight gave %v (code %q), want %q", name, err, Code(err), test.code)
		}
		if _, err := Inspect(test.data, testPassword); Code(err) != test.code {
			t.Fatalf("%s: Inspect gave %v, want the preflight refusal %q", name, err, test.code)
		}
	}
}

func bytesOf(count int, bag pfxfixture.Bag) []pfxfixture.Bag {
	out := make([]pfxfixture.Bag, count)
	for i := range out {
		out[i] = bag
	}
	return out
}

func attributesOf(count int, attribute pfxfixture.Attribute) []pfxfixture.Attribute {
	out := make([]pfxfixture.Attribute, count)
	for i := range out {
		out[i] = attribute
	}
	return out
}

func TestOpenLendsOnlyTheMatchingKeyAndRefusesNoCallback(t *testing.T) {
	c := newChain(t, false)
	data := pfxfixture.Windows(t, c.leaf, c.issuer, c.key, testPassword).Build(t)
	if err := Open(data, testPassword, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Open without a callback: %v", err)
	}
	refusal := errors.New("callback refusal")
	if err := Open(data, testPassword, func(Result, crypto.Signer) error { return refusal }); !errors.Is(err, refusal) {
		t.Fatalf("callback error was not returned: %v", err)
	}
	if err := Open(data, "wrong", func(Result, crypto.Signer) error { t.Fatal("key lent for a wrong password"); return nil }); Code(err) != "wrong-password" {
		t.Fatalf("wrong password: %v", err)
	}
	expectOpens(t, "Windows order", data, testPassword, c)
}

func TestIsPFXRecognisesContentNotName(t *testing.T) {
	data, certificate, _ := fixture(t)
	if !IsPFX(data) {
		t.Fatal("a PFX was not recognised")
	}
	key, err := x509.MarshalPKCS8PrivateKey(newChain(t, false).key)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range [][]byte{nil, certificate.Raw, key, []byte("PFX"), data[:len(data)-1]} {
		if IsPFX(other) {
			t.Fatal("something else was taken for a PFX")
		}
	}
}

func TestCodeNamesEachRefusal(t *testing.T) {
	for err, code := range map[error]string{nil: "", ErrWrongPassword: "wrong-password", ErrNotPFX: "not-pfx", ErrNoIntegrity: "no-integrity", ErrUnsupported: "unsupported", ErrInvalid: "contents"} {
		if Code(err) != code {
			t.Fatalf("Code(%v) = %q, want %q", err, Code(err), code)
		}
	}
}
