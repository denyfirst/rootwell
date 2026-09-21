package certverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestVerifyTLSServerCertificate(t *testing.T) {
	chain := newTestChain(t, leafServerAuth)
	result, err := Verify(chain.leafDER, Options{
		TrustBundle:        chain.rootPEM,
		IntermediateBundle: chain.intermediatePEM,
		Hostname:           "service.example.test",
		CurrentTime:        chain.now,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Hostname != "service.example.test" || !result.EvaluatedAt.Equal(chain.now) {
		t.Errorf("unexpected verification context: %#v", result)
	}
	if len(result.Chain) != 3 {
		t.Fatalf("chain length = %d, want 3", len(result.Chain))
	}
	if result.Chain[0].Subject != "CN=service.example.test" || result.Chain[2].Subject != "CN=Rootwell Test Root" {
		t.Errorf("unexpected verified chain: %#v", result.Chain)
	}
	for _, certificate := range result.Chain {
		if certificate.SHA256Fingerprint == "" {
			t.Error("verified chain contains an empty fingerprint")
		}
	}
}

func TestVerifyIgnoresUnusedPolicyIncompatibleAnchor(t *testing.T) {
	chain := newTestChain(t, leafServerAuth)
	legacyKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	legacyTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(999),
		Subject:               pkix.Name{CommonName: "Unused Legacy Root"},
		NotBefore:             chain.now.Add(-time.Hour),
		NotAfter:              chain.now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	legacyDER, err := x509.CreateCertificate(rand.Reader, legacyTemplate, legacyTemplate, legacyKey.Public(), legacyKey)
	if err != nil {
		t.Fatal(err)
	}
	trustBundle := append(append([]byte{}, chain.rootPEM...), certificatePEM(legacyDER)...)

	if _, err := Verify(chain.leafDER, Options{
		TrustBundle:        trustBundle,
		IntermediateBundle: chain.intermediatePEM,
		Hostname:           "service.example.test",
		CurrentTime:        chain.now,
	}); err != nil {
		t.Fatalf("Verify() rejected a valid chain because of an unused anchor: %v", err)
	}
}

func TestSelectPolicyCompliantChain(t *testing.T) {
	allowed := &x509.Certificate{
		Raw:                []byte("allowed"),
		SignatureAlgorithm: x509.PureEd25519,
		PublicKey:          make(ed25519.PublicKey, ed25519.PublicKeySize),
	}
	disallowed := &x509.Certificate{
		Raw:                []byte("disallowed"),
		SignatureAlgorithm: x509.SHA1WithRSA,
		PublicKey:          make(ed25519.PublicKey, ed25519.PublicKeySize),
	}
	chain, err := selectPolicyCompliantChain([][]*x509.Certificate{{disallowed}, {allowed}})
	if err != nil {
		t.Fatalf("selectPolicyCompliantChain() error = %v", err)
	}
	if len(chain) != 1 || chain[0] != allowed {
		t.Fatalf("selectPolicyCompliantChain() selected %#v, want allowed chain", chain)
	}
	if _, err := selectPolicyCompliantChain([][]*x509.Certificate{{disallowed}}); !errors.Is(err, ErrDisallowedSignatureAlgorithm) {
		t.Fatalf("selectPolicyCompliantChain() error = %v, want %v", err, ErrDisallowedSignatureAlgorithm)
	}
	if _, err := selectPolicyCompliantChain(nil); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("selectPolicyCompliantChain(nil) error = %v, want %v", err, ErrVerificationFailed)
	}
}

func TestVerifyClassifiesFailures(t *testing.T) {
	chain := newTestChain(t, leafServerAuth)
	clientChain := newTestChain(t, leafClientAuth)
	otherChain := newTestChainWithSeed(t, leafServerAuth, 0x61)
	base := Options{
		TrustBundle:        chain.rootPEM,
		IntermediateBundle: chain.intermediatePEM,
		Hostname:           "service.example.test",
		CurrentTime:        chain.now,
	}
	tests := []struct {
		name    string
		leaf    []byte
		options Options
		wantErr error
	}{
		{name: "missing hostname", leaf: chain.leafDER, options: replaceHostname(base, ""), wantErr: ErrInvalidHostname},
		{name: "wildcard hostname", leaf: chain.leafDER, options: replaceHostname(base, "*.example.test"), wantErr: ErrInvalidHostname},
		{name: "invalid time", leaf: chain.leafDER, options: replaceTime(base, time.Time{}), wantErr: ErrInvalidCurrentTime},
		{name: "leaf is CA", leaf: chain.rootDER, options: base, wantErr: ErrLeafIsCA},
		{name: "missing intermediate", leaf: chain.leafDER, options: replaceIntermediates(base, nil), wantErr: ErrUnknownAuthority},
		{name: "wrong root", leaf: chain.leafDER, options: replaceRoot(base, otherChain.rootPEM), wantErr: ErrUnknownAuthority},
		{name: "hostname mismatch", leaf: chain.leafDER, options: replaceHostname(base, "other.example.test"), wantErr: ErrHostnameMismatch},
		{name: "expired", leaf: chain.leafDER, options: replaceTime(base, chain.leafNotAfter.Add(time.Second)), wantErr: ErrExpired},
		{name: "not yet valid", leaf: chain.leafDER, options: replaceTime(base, chain.leafNotBefore.Add(-time.Second)), wantErr: ErrNotYetValid},
		{name: "client usage only", leaf: clientChain.leafDER, options: Options{TrustBundle: clientChain.rootPEM, IntermediateBundle: clientChain.intermediatePEM, Hostname: "service.example.test", CurrentTime: clientChain.now}, wantErr: ErrIncompatibleUsage},
		{name: "malformed leaf", leaf: []byte("not a certificate"), options: base, wantErr: ErrInvalidLeaf},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Verify(test.leaf, test.options)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Verify() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestValidHostnameInput(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{name: "dns name", hostname: "service.example.test", want: true},
		{name: "punycode", hostname: "xn--mnasib-q2a.example", want: true},
		{name: "empty"},
		{name: "wildcard", hostname: "*.example.test"},
		{name: "space", hostname: "service .example.test"},
		{name: "control", hostname: "service\n.example.test"},
		{name: "unicode requires punycode", hostname: "münasib.example"},
		{name: "too long", hostname: string(bytes.Repeat([]byte{'a'}, 254))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validHostnameInput(test.hostname); got != test.want {
				t.Fatalf("validHostnameInput() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestClassifyVerificationErrorUsesFailingCertificateTime(t *testing.T) {
	leaf := &x509.Certificate{
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	intermediate := &x509.Certificate{
		NotBefore: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	currentTime := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	err := x509.CertificateInvalidError{Cert: intermediate, Reason: x509.Expired}
	if got := classifyVerificationError(err, leaf, currentTime); !errors.Is(got, ErrNotYetValid) {
		t.Fatalf("classifyVerificationError() = %v, want %v", got, ErrNotYetValid)
	}
}

func replaceHostname(options Options, hostname string) Options {
	options.Hostname = hostname
	return options
}

func replaceTime(options Options, currentTime time.Time) Options {
	options.CurrentTime = currentTime
	return options
}

func replaceIntermediates(options Options, bundle []byte) Options {
	options.IntermediateBundle = bundle
	return options
}

func replaceRoot(options Options, bundle []byte) Options {
	options.TrustBundle = bundle
	return options
}

type leafUsage int

const (
	leafServerAuth leafUsage = iota
	leafClientAuth
)

type testChain struct {
	now             time.Time
	leafNotBefore   time.Time
	leafNotAfter    time.Time
	rootDER         []byte
	rootPEM         []byte
	intermediatePEM []byte
	leafDER         []byte
}

func newTestChain(t testing.TB, usage leafUsage) testChain {
	return newTestChainWithSeed(t, usage, 0x31)
}

func newTestChainWithSeed(t testing.TB, usage leafUsage, seedByte byte) testChain {
	t.Helper()
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	rootKey := testPrivateKey(seedByte)
	intermediateKey := testPrivateKey(seedByte + 1)
	leafKey := testPrivateKey(seedByte + 2)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(seedByte)),
		Subject:               pkix.Name{CommonName: "Rootwell Test Root"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          []byte{seedByte, 1},
	}
	rootDER := createCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	rootCertificate := parseCertificate(t, rootDER)

	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(seedByte) + 100),
		Subject:               pkix.Name{CommonName: "Rootwell Test Intermediate"},
		NotBefore:             now.Add(-12 * time.Hour),
		NotAfter:              now.Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          []byte{seedByte, 2},
	}
	intermediateDER := createCertificate(t, intermediateTemplate, rootCertificate, intermediateKey.Public(), rootKey)
	intermediateCertificate := parseCertificate(t, intermediateDER)

	extendedUsage := x509.ExtKeyUsageServerAuth
	if usage == leafClientAuth {
		extendedUsage = x509.ExtKeyUsageClientAuth
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(seedByte) + 200),
		Subject:               pkix.Name{CommonName: "service.example.test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{extendedUsage},
		BasicConstraintsValid: true,
		DNSNames:              []string{"service.example.test"},
	}
	leafDER := createCertificate(t, leafTemplate, intermediateCertificate, leafKey.Public(), intermediateKey)
	return testChain{
		now:             now,
		leafNotBefore:   leafTemplate.NotBefore,
		leafNotAfter:    leafTemplate.NotAfter,
		rootDER:         rootDER,
		rootPEM:         certificatePEM(rootDER),
		intermediatePEM: certificatePEM(intermediateDER),
		leafDER:         leafDER,
	}
}

func testPrivateKey(seedByte byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
}

func createCertificate(t testing.TB, template, parent *x509.Certificate, publicKey any, signer ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func parseCertificate(t testing.TB, der []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func certificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
