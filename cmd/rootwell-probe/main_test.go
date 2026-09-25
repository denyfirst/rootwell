package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/limits"
)

const testHostname = "probe.rootwell.invalid"

type probeFixture struct {
	rootPEM, leafPEM []byte
	rootPin          string
	server           tls.Certificate
}

func makeProbeFixture(t *testing.T) probeFixture {
	return makeProbeFixtureWithIntermediate(t, false)
}

func makeProbeFixtureWithIntermediate(t *testing.T, withIntermediate bool) probeFixture {
	t.Helper()
	now := time.Now()
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local probe test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	signer := root
	var signerKey ed25519.PrivateKey = rootKey
	var intermediateDER []byte
	if withIntermediate {
		intermediatePublic, intermediateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		intermediateTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Local probe test intermediate"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		}
		intermediateDER, err = x509.CreateCertificate(rand.Reader, intermediateTemplate, root, intermediatePublic, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		signer, err = x509.ParseCertificate(intermediateDER)
		if err != nil {
			t.Fatal(err)
		}
		signerKey = intermediateKey
	}
	leafPublic, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: testHostname},
		DNSNames: []string{testHostname}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, signer, leafPublic, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(rootDER)
	serverChain := [][]byte{leafDER}
	if withIntermediate {
		serverChain = append(serverChain, intermediateDER)
	}
	return probeFixture{
		rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		leafPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		rootPin: hex.EncodeToString(digest[:]),
		server:  tls.Certificate{Certificate: serverChain, PrivateKey: leafKey},
	}
}

func startTestServer(t *testing.T, certificate tls.Certificate) (string, int, *atomic.Int32) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				if tlsConnection, ok := connection.(*tls.Conn); ok {
					_ = tlsConnection.Handshake()
				}
			}()
		}
	}()
	address := listener.Addr().(*net.TCPAddr)
	return "127.0.0.1", address.Port, &accepted
}

func writeFixture(t *testing.T, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func probeArgs(ip string, port int, rootPath, rootPin, leafPath string) []string {
	return []string{"--hostname", testHostname, "--connect-ip", ip, "--port", strconv.Itoa(port),
		"--trust-bundle", rootPath, "--root-sha256", rootPin, "--expected-leaf", leafPath}
}

func TestLiveProbeMatchesPinnedRootAndServedLeaf(t *testing.T) {
	fixture := makeProbeFixture(t)
	ip, port, accepted := startTestServer(t, fixture.server)
	other := makeProbeFixture(t)
	rootPath := writeFixture(t, "roots.pem", append(bytes.Clone(other.rootPEM), fixture.rootPEM...))
	leafPath := writeFixture(t, "leaf.pem", fixture.leafPEM)
	var stdout, stderr bytes.Buffer
	if code := run(probeArgs(ip, port, rootPath, fixture.rootPin, leafPath), &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d, stderr=%q", code, stderr.String())
	}
	if stderr.Len() != 0 || !strings.Contains(stdout.String(), "live-tls: passed\n") ||
		!strings.Contains(stdout.String(), "expected-leaf-sha256:") ||
		!strings.Contains(stdout.String(), "root-pin-sha256:") ||
		!strings.Contains(stdout.String(), "revocation: not-checked\n") {
		t.Fatalf("unexpected output: %q, %q", stdout.String(), stderr.String())
	}
	if accepted.Load() != 1 {
		t.Fatalf("expected one connection, got %d", accepted.Load())
	}
	for path, expected := range map[string][]byte{
		rootPath: append(bytes.Clone(other.rootPEM), fixture.rootPEM...),
		leafPath: fixture.leafPEM,
	} {
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("probe changed a public input file")
		}
	}
}

func TestLiveProbeRequiresPeerToServeIntermediate(t *testing.T) {
	fixture := makeProbeFixtureWithIntermediate(t, true)
	rootPath := writeFixture(t, "root.pem", fixture.rootPEM)
	leafPath := writeFixture(t, "leaf.pem", fixture.leafPEM)
	completeIP, completePort, _ := startTestServer(t, fixture.server)
	var stdout, stderr bytes.Buffer
	if code := run(probeArgs(completeIP, completePort, rootPath, fixture.rootPin, leafPath), &stdout, &stderr); code != 0 {
		t.Fatalf("complete peer chain refused: code=%d stderr=%q", code, stderr.String())
	}
	missing := fixture.server
	missing.Certificate = missing.Certificate[:1]
	missingIP, missingPort, _ := startTestServer(t, missing)
	stdout.Reset()
	stderr.Reset()
	if code := run(probeArgs(missingIP, missingPort, rootPath, fixture.rootPin, leafPath), &stdout, &stderr); code != 1 ||
		stdout.Len() != 0 || stderr.String() != "TLS connection or verification failed\n" {
		t.Fatalf("missing peer intermediate accepted: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestLiveProbeRefusesMismatchAndPreNetworkFailures(t *testing.T) {
	fixture := makeProbeFixture(t)
	ip, port, accepted := startTestServer(t, fixture.server)
	rootPath := writeFixture(t, "root.pem", fixture.rootPEM)
	leafPath := writeFixture(t, "leaf.pem", fixture.leafPEM)
	other := makeProbeFixture(t)
	otherLeafPath := writeFixture(t, "other-leaf.pem", other.leafPEM)
	for _, test := range []struct {
		name, rootPath, rootPin, leafPath, hostname string
		wantNetwork                                 bool
		wantError                                   string
	}{
		{"different leaf", rootPath, fixture.rootPin, otherLeafPath, testHostname, true, "served leaf differs"},
		{"different pinned root", rootPath, other.rootPin, leafPath, testHostname, false, "root fingerprint"},
		{"invalid trust", writeFixture(t, "invalid-root.pem", []byte("not a PEM certificate")), fixture.rootPin, leafPath, testHostname, false, "invalid trust bundle"},
		{"secret instead of expected leaf", rootPath, fixture.rootPin,
			writeFixture(t, "private.pem", []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")),
			testHostname, false, "invalid expected leaf certificate"},
		{"missing file", "secret-path-marker", fixture.rootPin, leafPath, testHostname, false, "trust bundle could not be read"},
		{"wrong hostname", rootPath, fixture.rootPin, leafPath, "other.rootwell.invalid", true, "TLS connection or verification failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := accepted.Load()
			args := probeArgs(ip, port, test.rootPath, test.rootPin, test.leafPath)
			args[1] = test.hostname
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 1 || stdout.Len() != 0 ||
				!strings.Contains(stderr.String(), test.wantError) || strings.Contains(stderr.String(), "secret-path-marker") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if (accepted.Load() > before) != test.wantNetwork {
				t.Fatalf("unexpected network behavior for %s", test.name)
			}
		})
	}
}

func TestLiveProbeRejectsMalformedArgumentsBeforeNetwork(t *testing.T) {
	fixture := makeProbeFixture(t)
	ip, port, accepted := startTestServer(t, fixture.server)
	rootPath := writeFixture(t, "root.pem", fixture.rootPEM)
	leafPath := writeFixture(t, "leaf.pem", fixture.leafPEM)
	base := probeArgs(ip, port, rootPath, fixture.rootPin, leafPath)
	for _, changed := range [][]string{
		base[:len(base)-1],
		func() []string { v := append([]string(nil), base...); v[2] = "--hostname"; return v }(),
		func() []string { v := append([]string(nil), base...); v[3] = "https://127.0.0.1"; return v }(),
		func() []string { v := append([]string(nil), base...); v[3] = "example.com"; return v }(),
		func() []string { v := append([]string(nil), base...); v[5] = "0"; return v }(),
		func() []string { v := append([]string(nil), base...); v[9] = fixture.rootPin[:62]; return v }(),
		func() []string { v := append([]string(nil), base...); v[1] = "bad/name"; return v }(),
	} {
		before := accepted.Load()
		var stdout, stderr bytes.Buffer
		if code := run(changed, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != "invalid arguments\n" {
			t.Fatalf("malformed request: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if accepted.Load() != before {
			t.Fatal("malformed arguments caused a connection")
		}
	}
}

func TestProbeHelpAndVersionAreOffline(t *testing.T) {
	for _, input := range []string{"--help", "--version"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{input}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || stdout.Len() == 0 {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q", input, code, stdout.String(), stderr.String())
		}
	}
}

func TestProbeOutputFailureIsNotSuccess(t *testing.T) {
	if code := write(failingWriter{}, "live-tls: passed\n", 0); code != 1 {
		t.Fatalf("output failure exit code = %d", code)
	}
}

func TestFullFingerprintParsing(t *testing.T) {
	plain := strings.Repeat("aB", sha256.Size)
	colon := strings.Join(strings.Fields(strings.Repeat("aB ", sha256.Size)), ":")
	first, ok := parseFingerprint(plain)
	if !ok {
		t.Fatal("complete plain fingerprint refused")
	}
	second, ok := parseFingerprint(colon)
	if !ok || first != second {
		t.Fatal("equivalent colon-separated fingerprint refused")
	}
	for _, malformed := range []string{
		"", plain[:62], plain + "00", " " + plain, plain[:63] + "Z",
		strings.Replace(colon, ":", "-", 1), colon + ":00",
	} {
		if _, accepted := parseFingerprint(malformed); accepted {
			t.Fatalf("malformed fingerprint was accepted: %q", malformed)
		}
	}
}

func TestObservedChainResourceLimits(t *testing.T) {
	var digest [sha256.Size]byte
	for _, chain := range [][]*x509.Certificate{
		make([]*x509.Certificate, limits.MaxCertificatesPerBundle+1),
		{{Raw: make([]byte, int(limits.MaxInputBytes)+1)}},
		{nil},
	} {
		if err := verifyObserved(tls.ConnectionState{PeerCertificates: chain}, digest, digest,
			[]byte("unused"), testHostname, time.Now()); !errors.Is(err, errLivePolicy) {
			t.Fatalf("oversized chain was not refused: %v", err)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }
