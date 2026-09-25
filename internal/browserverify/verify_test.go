package browserverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

type testChain struct {
	leafDER, leafPEM, intermediatePEM, rootPEM []byte
	now                                        time.Time
}

func makeChain(t testing.TB) testChain {
	t.Helper()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	makeKey := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return public, private
	}
	rootPublic, rootKey := makeKey()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Explicit Test Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		MaxPathLen: 1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediatePublic, intermediateKey := makeKey()
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(180 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		MaxPathLenZero: true,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, intermediatePublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafKey := makeKey()
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "verify.rootwell.invalid"},
		DNSNames:  []string{"verify.rootwell.invalid"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, leafPublic, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = leafKey
	toPEM := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	return testChain{leafDER: leafDER, leafPEM: toPEM(leafDER), intermediatePEM: toPEM(intermediateDER), rootPEM: toPEM(rootDER), now: now}
}

func decode(t testing.TB, encoded string) Response {
	t.Helper()
	var response Response
	if err := json.Unmarshal([]byte(encoded), &response); err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != SchemaVersion {
		t.Fatalf("schema = %q", response.SchemaVersion)
	}
	return response
}

func TestSimpleAndExplicitUseSameTrustVerdict(t *testing.T) {
	chain := makeChain(t)
	sources := [][]byte{append(append(bytes.Clone(chain.leafPEM), chain.intermediatePEM...), chain.rootPEM...)}
	simple := decode(t, Simple(sources, chain.rootPEM, "verify.rootwell.invalid", chain.now))
	explicit := decode(t, Explicit(chain.leafDER, chain.intermediatePEM, chain.rootPEM, "verify.rootwell.invalid", chain.now))
	if !simple.OK || !explicit.OK || simple.Result == nil || explicit.Result == nil {
		t.Fatalf("simple = %#v, explicit = %#v", simple, explicit)
	}
	if simple.Result.IgnoredSourceRoots != 1 || explicit.Result.IgnoredSourceRoots != 0 ||
		simple.Result.TrustSource != "explicit-file" || simple.Result.Network != "disabled" ||
		simple.Result.Revocation != "not-checked" || simple.Result.Verification != "passed" ||
		len(simple.Result.Chain) != 3 || !reflect.DeepEqual(simple.Result.Chain, explicit.Result.Chain) {
		t.Fatalf("mismatched verification: simple = %#v, explicit = %#v", simple.Result, explicit.Result)
	}
}

func TestSimpleNeverTrustsSourceRoot(t *testing.T) {
	chain := makeChain(t)
	other := makeChain(t)
	sources := [][]byte{chain.leafPEM, append(bytes.Clone(chain.intermediatePEM), chain.rootPEM...)}
	for _, test := range []struct {
		name  string
		trust []byte
		want  string
	}{
		{"missing trust", nil, "invalid-browser-request"},
		{"different trust", other.rootPEM, "unknown-authority"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := decode(t, Simple(sources, test.trust, "verify.rootwell.invalid", chain.now))
			if response.OK || response.Result != nil || response.Error == nil || response.Error.Code != test.want {
				t.Fatalf("unexpected trust result = %#v", response)
			}
		})
	}
}

func TestRootPinMatchesOnlyCompleteVerifiedPathAnchor(t *testing.T) {
	chain := makeChain(t)
	rootBlock, _ := pem.Decode(chain.rootPEM)
	if rootBlock == nil {
		t.Fatal("missing test root")
	}
	digest := sha256.Sum256(rootBlock.Bytes)
	plain := strings.ToUpper(hex.EncodeToString(digest[:]))
	colon := strings.Join(splitHexBytes(plain), ":")
	for _, pin := range []string{plain, strings.ToLower(colon)} {
		for _, encoded := range []string{
			SimpleWithRootPin([][]byte{chain.leafPEM, chain.intermediatePEM}, chain.rootPEM, "verify.rootwell.invalid", chain.now, pin),
			ExplicitWithRootPin(chain.leafDER, chain.intermediatePEM, chain.rootPEM, "verify.rootwell.invalid", chain.now, pin),
		} {
			response := decode(t, encoded)
			if !response.OK || response.Result == nil || response.Result.RootPin != "matched" ||
				response.Result.Chain[len(response.Result.Chain)-1].SHA256Fingerprint != colon {
				t.Fatalf("valid root pin refused: %#v", response)
			}
		}
	}
	other := makeChain(t)
	otherBlock, _ := pem.Decode(other.rootPEM)
	if otherBlock == nil {
		t.Fatal("missing alternate test root")
	}
	otherDigest := sha256.Sum256(otherBlock.Bytes)
	trustBundle := append(bytes.Clone(other.rootPEM), chain.rootPEM...)
	chosen := decode(t, ExplicitWithRootPin(chain.leafDER, chain.intermediatePEM, trustBundle,
		"verify.rootwell.invalid", chain.now, plain))
	if !chosen.OK || chosen.Result == nil || chosen.Result.RootPin != "matched" {
		t.Fatalf("pin must target verified path's root, not first bundle member: %#v", chosen)
	}
	wrongBundleMember := decode(t, ExplicitWithRootPin(chain.leafDER, chain.intermediatePEM, trustBundle,
		"verify.rootwell.invalid", chain.now, hex.EncodeToString(otherDigest[:])))
	if wrongBundleMember.OK || wrongBundleMember.Error == nil || wrongBundleMember.Error.Code != "root-pin-mismatch" {
		t.Fatalf("unselected bundle root must not satisfy pin: %#v", wrongBundleMember)
	}
	for _, test := range []struct{ pin, want string }{
		{strings.Repeat("00", 32), "root-pin-mismatch"},
		{plain[:62], "invalid-root-pin"},
		{plain + "00", "invalid-root-pin"},
		{strings.Replace(colon, ":", "-", 1), "invalid-root-pin"},
		{plain[:63] + "Z", "invalid-root-pin"},
		{" SHA256:" + plain, "invalid-root-pin"},
	} {
		response := decode(t, ExplicitWithRootPin(chain.leafDER, chain.intermediatePEM, chain.rootPEM,
			"verify.rootwell.invalid", chain.now, test.pin))
		if response.OK || response.Result != nil || response.Error == nil || response.Error.Code != test.want {
			t.Fatalf("pin %q: %#v", test.pin, response)
		}
	}
	unpinned := decode(t, Explicit(chain.leafDER, chain.intermediatePEM, chain.rootPEM, "verify.rootwell.invalid", chain.now))
	if !unpinned.OK || unpinned.Result == nil || unpinned.Result.RootPin != "not-provided" {
		t.Fatalf("unpinned status = %#v", unpinned)
	}
}

func splitHexBytes(value string) []string {
	parts := make([]string, 0, 32)
	for index := 0; index < len(value); index += 2 {
		parts = append(parts, value[index:index+2])
	}
	return parts
}

func TestSimpleRejectsAmbiguousAndSecretSources(t *testing.T) {
	chain := makeChain(t)
	other := makeChain(t)
	secret := []byte("-----BEGIN PRIVATE KEY-----\nsecret-marker\n-----END PRIVATE KEY-----")
	for _, test := range []struct {
		name    string
		sources [][]byte
		want    string
	}{
		{"two leaves", [][]byte{chain.leafPEM, other.leafPEM}, "ambiguous-leaf"},
		{"no leaf", [][]byte{chain.rootPEM}, "missing-leaf"},
		{"secret", [][]byte{chain.leafPEM, secret}, "invalid-public-source"},
		{"duplicate", [][]byte{chain.leafPEM, chain.leafPEM}, "duplicate-certificate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded := Simple(test.sources, chain.rootPEM, "verify.rootwell.invalid", chain.now)
			response := decode(t, encoded)
			if response.OK || response.Result != nil || response.Error == nil || response.Error.Code != test.want ||
				strings.Contains(encoded, "secret-marker") || strings.Contains(encoded, "verify.rootwell.invalid") {
				t.Fatalf("unsafe response = %s", encoded)
			}
		})
	}
}

func TestExplicitClassifiesRefusalsWithoutPartialChain(t *testing.T) {
	chain := makeChain(t)
	for _, test := range []struct {
		name, hostname string
		trust          []byte
		now            time.Time
		want           string
	}{
		{"wrong hostname", "other.rootwell.invalid", chain.rootPEM, chain.now, "hostname-mismatch"},
		{"expired", "verify.rootwell.invalid", chain.rootPEM, chain.now.Add(200 * 24 * time.Hour), "expired"},
		{"missing trust", "verify.rootwell.invalid", nil, chain.now, "invalid-trust-bundle"},
		{"invalid time", "verify.rootwell.invalid", chain.rootPEM, time.Time{}, "invalid-time"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := decode(t, Explicit(chain.leafPEM, chain.intermediatePEM, test.trust, test.hostname, test.now))
			if response.OK || response.Result != nil || response.Error == nil || response.Error.Code != test.want {
				t.Fatalf("response = %#v", response)
			}
		})
	}
}

func FuzzSimpleNeverUsesSourceAsTrust(f *testing.F) {
	chain := makeChain(f)
	f.Add(chain.leafPEM)
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"))
	f.Fuzz(func(t *testing.T, source []byte) {
		response := decode(t, Simple([][]byte{source}, chain.rootPEM, "verify.rootwell.invalid", chain.now))
		if response.OK && (response.Result == nil || response.Result.TrustSource != "explicit-file" || response.Result.Verification != "passed") {
			t.Fatal("source changed the trust model")
		}
	})
}
