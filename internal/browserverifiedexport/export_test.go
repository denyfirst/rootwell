package browserverifiedexport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/browserverify"
	"github.com/denyfirst/rootwell/internal/publicbundle"
)

type fixture struct {
	leaf, intermediate, root, source []byte
	hostname                         string
	now                              time.Time
	chain                            []string
}

func makeFixture(t testing.TB) fixture {
	t.Helper()
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return public, private
	}
	rootPublic, rootKey := key()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Verified Export Test Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediatePublic, intermediateKey := key()
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Verified Export Test Intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(180 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, intermediatePublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, _ := key()
	const hostname = "verify.rootwell.invalid"
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, leafPublic, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	f := fixture{leaf: encode(leafDER), intermediate: encode(intermediateDER), root: encode(rootDER), hostname: hostname, now: now}
	f.source = append(append(bytes.Clone(f.leaf), f.intermediate...), f.root...)
	var verified browserverify.Response
	if err := json.Unmarshal([]byte(browserverify.Simple([][]byte{f.source}, f.root, hostname, now)), &verified); err != nil || !verified.OK {
		t.Fatalf("fixture did not verify: %v, %#v", err, verified)
	}
	for _, member := range verified.Result.Chain {
		f.chain = append(f.chain, member.SHA256Fingerprint)
	}
	return f
}

func TestPrepareVerifiedFullchainExcludesRootAndPreservesVerifiedOrder(t *testing.T) {
	f := makeFixture(t)
	simple, code := PrepareSimple([][]byte{f.source}, f.root, f.hostname, f.now, f.chain)
	if code != "" {
		t.Fatalf("Simple code = %q", code)
	}
	defer clear(simple.Bytes)
	unordered := append(append(bytes.Clone(f.root), f.leaf...), f.intermediate...)
	reordered, code := PrepareSimple([][]byte{unordered}, f.root, f.hostname, f.now, f.chain)
	if code != "" || !bytes.Equal(reordered.Bytes, simple.Bytes) {
		t.Fatalf("unordered source was not exported in verified path order: %q", code)
	}
	defer clear(reordered.Bytes)
	explicit, code := PrepareExplicit(f.leaf, f.intermediate, f.root, f.hostname, f.now, f.chain)
	if code != "" {
		t.Fatalf("Explicit code = %q", code)
	}
	defer clear(explicit.Bytes)
	if !reflect.DeepEqual(simple.Fingerprints, f.chain[:2]) || !reflect.DeepEqual(explicit.Fingerprints, f.chain[:2]) ||
		!bytes.Equal(simple.Bytes, explicit.Bytes) || simple.Hostname != f.hostname ||
		simple.EvaluatedAt != f.now.Format(time.RFC3339Nano) ||
		!strings.HasPrefix(simple.Filename, "rootwell-verified-fullchain-") ||
		!strings.HasSuffix(simple.Filename, ".pem") ||
		simple.Filename == explicit.Filename {
		t.Fatalf("unexpected export metadata: simple=%#v explicit=%#v", simple, explicit)
	}
	entries, err := publicbundle.Parse(simple.Bytes)
	if err != nil || len(entries) != 2 {
		t.Fatalf("output parsing: %v, count=%d", err, len(entries))
	}
	for index, entry := range entries {
		if entry.Inspection.SHA256Fingerprint != f.chain[index] {
			t.Fatalf("output index %d has wrong fingerprint", index)
		}
	}
	if bytes.Contains(simple.Bytes, f.root) || bytes.Contains(simple.Bytes, []byte("PRIVATE KEY")) {
		t.Fatal("trust root or private key appeared in output")
	}
}

func TestPrepareRefusesUnverifiedChangedAndUnsafeInputs(t *testing.T) {
	f := makeFixture(t)
	other := makeFixture(t)
	badChain := append([]string(nil), f.chain...)
	badChain[1] = other.chain[1]
	reorderedChain := []string{f.chain[1], f.chain[0], f.chain[2]}
	secret := []byte("-----BEGIN PRIVATE KEY-----\nsecret-marker\n-----END PRIVATE KEY-----\n")
	oversized := make([]byte, 16*1024*1024+1)
	for _, test := range []struct {
		name     string
		sources  [][]byte
		trust    []byte
		hostname string
		now      time.Time
		expected []string
		want     ErrorCode
	}{
		{"wrong root", [][]byte{f.source}, other.root, f.hostname, f.now, f.chain, ErrorNotVerified},
		{"wrong host", [][]byte{f.source}, f.root, "other.rootwell.invalid", f.now, f.chain, ErrorNotVerified},
		{"expired", [][]byte{f.source}, f.root, f.hostname, f.now.Add(200 * 24 * time.Hour), f.chain, ErrorNotVerified},
		{"changed path", [][]byte{f.source}, f.root, f.hostname, f.now, badChain, ErrorChangedVerdict},
		{"reordered path", [][]byte{f.source}, f.root, f.hostname, f.now, reorderedChain, ErrorChangedVerdict},
		{"secret source", [][]byte{secret}, f.root, f.hostname, f.now, f.chain, ErrorInvalidSource},
		{"duplicate source", [][]byte{f.source, f.leaf}, f.root, f.hostname, f.now, f.chain, ErrorNotVerified},
		{"missing expected", [][]byte{f.source}, f.root, f.hostname, f.now, nil, ErrorInvalidRequest},
		{"duplicate expected", [][]byte{f.source}, f.root, f.hostname, f.now, []string{f.chain[0], f.chain[0]}, ErrorInvalidRequest},
		{"oversized", [][]byte{oversized}, f.root, f.hostname, f.now, f.chain, ErrorTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, code := PrepareSimple(test.sources, test.trust, test.hostname, test.now, test.expected)
			if code != test.want || len(result.Bytes) != 0 || strings.Contains(string(result.Bytes), "secret-marker") {
				t.Fatalf("code = %q, output = %#v", code, result)
			}
		})
	}
}

func TestPrepareExplicitNeedsSameVerifiedPath(t *testing.T) {
	f := makeFixture(t)
	other := makeFixture(t)
	for _, test := range []struct {
		name                      string
		leaf, intermediate, trust []byte
		want                      ErrorCode
	}{
		{"wrong trust", f.leaf, f.intermediate, other.root, ErrorNotVerified},
		{"missing intermediate", f.leaf, nil, f.root, ErrorNotVerified},
		{"private key", []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"), f.intermediate, f.root, ErrorNotVerified},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, code := PrepareExplicit(test.leaf, test.intermediate, test.trust, f.hostname, f.now, f.chain)
			if code != test.want || len(result.Bytes) != 0 {
				t.Fatalf("code = %q, output = %#v", code, result)
			}
		})
	}
}

func FuzzPrepareNeverExportsUnverifiedSource(f *testing.F) {
	fixture := makeFixture(f)
	f.Add(fixture.source)
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n"))
	f.Fuzz(func(t *testing.T, source []byte) {
		result, code := PrepareSimple([][]byte{source}, fixture.root, fixture.hostname, fixture.now, fixture.chain)
		if code != "" {
			if len(result.Bytes) != 0 {
				t.Fatal("failed export returned bytes")
			}
			return
		}
		defer clear(result.Bytes)
		if !reflect.DeepEqual(result.Fingerprints, fixture.chain[:2]) {
			t.Fatal("exported fingerprints differ from verified path")
		}
		entries, err := publicbundle.Parse(result.Bytes)
		if err != nil || len(entries) != 2 || entries[0].Inspection.SHA256Fingerprint != fixture.chain[0] ||
			entries[1].Inspection.SHA256Fingerprint != fixture.chain[1] {
			t.Fatal("exported bytes differ from verified path")
		}
	})
}
