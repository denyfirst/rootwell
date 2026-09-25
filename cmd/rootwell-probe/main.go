// Command rootwell-probe performs one explicitly requested, read-only TLS
// endpoint check. Unlike the Rootwell Workbench, this executable has network
// capability and must never be exposed as an unauthenticated request proxy.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/certverify"
	"github.com/denyfirst/rootwell/internal/fileinput"
	"github.com/denyfirst/rootwell/internal/limits"
	"github.com/denyfirst/rootwell/internal/version"
)

const usage = "usage: rootwell-probe --hostname <dns-name> --connect-ip <ip> --port <1-65535> --trust-bundle <roots.pem> --root-sha256 <fingerprint> --expected-leaf <certificate>\n"

var (
	errLeafMismatch = errors.New("served leaf differs from expected certificate")
	errLivePolicy   = errors.New("served certificate fails Rootwell policy")
)

type options struct {
	hostname, connectIP, trustPath, expectedLeafPath string
	port                                             int
	rootPin                                          [sha256.Size]byte
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if stdout == nil || stderr == nil {
		return 1
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		return write(stdout, usage, 0)
	}
	if len(args) == 1 && args[0] == "--version" {
		return write(stdout, "rootwell-probe "+version.Value()+"\n", 0)
	}
	selected, valid := parseOptions(args)
	if !valid {
		return write(stderr, "invalid arguments\n", 2)
	}
	trustInput, err := fileinput.Read(selected.trustPath)
	if err != nil {
		return write(stderr, "trust bundle could not be read\n", 1)
	}
	defer clear(trustInput)
	anchors, err := certverify.ParseTrustAnchors(trustInput)
	if err != nil {
		return write(stderr, "invalid trust bundle\n", 1)
	}
	var pinnedRoot *x509.Certificate
	for _, anchor := range anchors {
		digest := sha256.Sum256(anchor.Raw)
		if subtle.ConstantTimeCompare(digest[:], selected.rootPin[:]) == 1 {
			pinnedRoot = anchor
		}
	}
	if pinnedRoot == nil {
		return write(stderr, "root fingerprint does not match trust bundle\n", 1)
	}
	leafInput, err := fileinput.Read(selected.expectedLeafPath)
	if err != nil {
		return write(stderr, "expected certificate could not be read\n", 1)
	}
	defer clear(leafInput)
	expectedLeaf, _, err := certinspect.Parse(leafInput)
	if err != nil || expectedLeaf.IsCA {
		return write(stderr, "invalid expected leaf certificate\n", 1)
	}
	expectedDigest := sha256.Sum256(expectedLeaf.Raw)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pinnedRoot.Raw})
	defer clear(rootPEM)
	roots := x509.NewCertPool()
	roots.AddCert(pinnedRoot)
	var observedAt time.Time
	config := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		RootCAs:                roots,
		ServerName:             selected.hostname,
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			observedAt = time.Now().UTC()
			return verifyObserved(state, expectedDigest, selected.rootPin, rootPEM, selected.hostname, observedAt)
		},
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	address := net.JoinHostPort(selected.connectIP, strconv.Itoa(selected.port))
	connection, err := tls.DialWithDialer(dialer, "tcp", address, config)
	if err != nil {
		if errors.Is(err, errLeafMismatch) {
			return write(stderr, "served leaf differs from expected certificate\n", 1)
		}
		return write(stderr, "TLS connection or verification failed\n", 1)
	}
	state := connection.ConnectionState()
	_ = connection.Close()
	version := "TLS 1.2"
	if state.Version == tls.VersionTLS13 {
		version = "TLS 1.3"
	}
	result := fmt.Sprintf("live-tls: passed\nhostname: %s\nconnect-ip: %s\nport: %d\ntls-version: %s\nevaluated-at: %s\nexpected-leaf-sha256: %s\nroot-pin-sha256: %s\nrevocation: not-checked\nnetwork: explicit-one-endpoint\n",
		selected.hostname, selected.connectIP, selected.port, version, observedAt.Format(time.RFC3339Nano), fingerprint(expectedDigest), fingerprint(selected.rootPin))
	return write(stdout, result, 0)
}

func verifyObserved(state tls.ConnectionState, expected, rootPin [sha256.Size]byte, rootPEM []byte, hostname string, now time.Time) error {
	if len(state.PeerCertificates) < 1 || len(state.PeerCertificates) > limits.MaxCertificatesPerBundle {
		return errLivePolicy
	}
	remaining := int(limits.MaxInputBytes)
	for _, certificate := range state.PeerCertificates {
		if certificate == nil || len(certificate.Raw) > remaining {
			return errLivePolicy
		}
		remaining -= len(certificate.Raw)
	}
	served := state.PeerCertificates[0]
	servedDigest := sha256.Sum256(served.Raw)
	if subtle.ConstantTimeCompare(servedDigest[:], expected[:]) != 1 {
		return errLeafMismatch
	}
	var intermediates []byte
	defer clear(intermediates)
	for _, certificate := range state.PeerCertificates[1:] {
		if bytes.Equal(certificate.RawIssuer, certificate.RawSubject) {
			digest := sha256.Sum256(certificate.Raw)
			if subtle.ConstantTimeCompare(digest[:], rootPin[:]) == 1 && certificate.CheckSignatureFrom(certificate) == nil {
				continue // A sent root is not promoted into trust or an intermediate.
			}
			return errLivePolicy
		}
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
		if len(block) == 0 || len(block) > int(limits.MaxInputBytes)-len(intermediates) {
			clear(block)
			return errLivePolicy
		}
		intermediates = append(intermediates, block...)
		clear(block)
	}
	result, err := certverify.Verify(served.Raw, certverify.Options{
		TrustBundle: rootPEM, IntermediateBundle: intermediates,
		Hostname: hostname, CurrentTime: now,
	})
	if err != nil || len(result.Chain) == 0 || result.Chain[len(result.Chain)-1].SHA256Fingerprint != fingerprint(rootPin) {
		return errLivePolicy
	}
	return nil
}

func parseOptions(args []string) (options, bool) {
	if len(args) != 12 {
		return options{}, false
	}
	values := make(map[string]string, 6)
	for index := 0; index < len(args); index += 2 {
		flag, value := args[index], args[index+1]
		if value == "" || values[flag] != "" {
			return options{}, false
		}
		switch flag {
		case "--hostname", "--connect-ip", "--port", "--trust-bundle", "--root-sha256", "--expected-leaf":
			values[flag] = value
		default:
			return options{}, false
		}
	}
	hostname := values["--hostname"]
	if !validDNSName(hostname) || net.ParseIP(hostname) != nil {
		return options{}, false
	}
	ip := net.ParseIP(values["--connect-ip"])
	if ip == nil {
		return options{}, false
	}
	portText := values["--port"]
	if portText == "" || len(portText) > 5 {
		return options{}, false
	}
	for _, digit := range portText {
		if digit < '0' || digit > '9' {
			return options{}, false
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return options{}, false
	}
	rootPin, ok := parseFingerprint(values["--root-sha256"])
	if !ok || values["--trust-bundle"] == "" || values["--expected-leaf"] == "" {
		return options{}, false
	}
	return options{hostname: hostname, connectIP: ip.String(), port: port,
		trustPath: values["--trust-bundle"], expectedLeafPath: values["--expected-leaf"], rootPin: rootPin}, true
}

func validDNSName(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') &&
				!(character >= '0' && character <= '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func parseFingerprint(value string) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	if len(value) == 95 {
		for index := 2; index < len(value); index += 3 {
			if value[index] != ':' {
				return digest, false
			}
		}
		value = strings.ReplaceAll(value, ":", "")
	}
	if len(value) != 64 {
		return digest, false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return digest, false
	}
	copy(digest[:], decoded)
	return digest, true
}

func fingerprint(digest [sha256.Size]byte) string {
	encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
	parts := make([]string, 0, sha256.Size)
	for index := 0; index < len(encoded); index += 2 {
		parts = append(parts, encoded[index:index+2])
	}
	return strings.Join(parts, ":")
}

func write(writer io.Writer, value string, code int) int {
	if written, err := io.WriteString(writer, value); err != nil || written != len(value) {
		return 1
	}
	return code
}
