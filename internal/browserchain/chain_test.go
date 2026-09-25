package browserchain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func makeCertificate(t *testing.T, serial int64, subject string, parent *x509.Certificate, signer ed25519.PrivateKey, ca bool) ([]byte, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: subject},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true, IsCA: ca,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent = template
		signer = private
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate, private
}

func parseResponse(t *testing.T, inputs [][]byte) Response {
	t.Helper()
	var response Response
	if err := json.Unmarshal([]byte(Process(inputs)), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestProcessFindsSignedCandidatesWithoutTrust(t *testing.T) {
	rootPEM, root, rootKey := makeCertificate(t, 1, "root.invalid", nil, nil, true)
	intermediatePEM, intermediate, intermediateKey := makeCertificate(t, 2, "intermediate.invalid", root, rootKey, true)
	leafPEM, _, _ := makeCertificate(t, 3, "leaf.invalid", intermediate, intermediateKey, false)
	roguePEM, _, _ := makeCertificate(t, 4, "intermediate.invalid", nil, nil, true)
	response := parseResponse(t, [][]byte{leafPEM, append(bytes.Clone(intermediatePEM), rootPEM...), roguePEM})
	if !response.OK || response.Error != "" || response.Result == nil || len(response.Result.Certificates) != 4 {
		t.Fatalf("response = %#v", response)
	}
	if response.Result.Verification != "not-performed" || response.Result.TrustAnchor != "not-selected" {
		t.Fatalf("analysis implied trust: %#v", response.Result)
	}
	items := response.Result.Certificates
	if !equalInts(items[0].Parents, []int{1}) || !equalInts(items[1].Parents, []int{2}) ||
		!items[2].SelfSigned || len(items[2].Parents) != 0 ||
		!items[3].SelfSigned || len(items[3].Parents) != 0 {
		t.Fatalf("unexpected issuer candidates: %#v", items)
	}
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestProcessRejectsUnsafeCollectionsWithoutEcho(t *testing.T) {
	certificate, _, _ := makeCertificate(t, 1, "private.invalid", nil, nil, true)
	secret := []byte("-----BEGIN PRIVATE KEY-----\nsecret-marker\n-----END PRIVATE KEY-----")
	for _, inputs := range [][][]byte{
		nil,
		{certificate, certificate},
		{certificate, secret},
		{certificate, []byte("trailing-marker")},
		{make([]byte, 16<<20+1)},
		{certificate, make([]byte, 16<<20)},
	} {
		encoded := Process(inputs)
		response := parseResponse(t, inputs)
		if response.OK || response.Result != nil || response.Error == "" ||
			strings.Contains(encoded, "secret-marker") || strings.Contains(encoded, "private.invalid") ||
			strings.Contains(encoded, "trailing-marker") {
			t.Fatalf("unsafe response = %s", encoded)
		}
	}
}

func TestProcessBoundsSignatureWork(t *testing.T) {
	var bundle []byte
	for serial := int64(1); serial <= 17; serial++ {
		certificate, _, _ := makeCertificate(t, serial, "same-subject.invalid", nil, nil, true)
		bundle = append(bundle, certificate...)
	}
	response := parseResponse(t, [][]byte{bundle})
	if response.OK || response.Result != nil || response.Error != "invalid-public-collection" {
		t.Fatalf("signature work limit: %#v", response)
	}
}

func FuzzProcessNeverReturnsTrust(f *testing.F) {
	f.Add([]byte("not a certificate"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"))
	f.Fuzz(func(t *testing.T, input []byte) {
		encoded := Process([][]byte{input})
		if len(encoded) > maxResponseBytes {
			t.Fatal("response exceeds analysis limit")
		}
		var response Response
		if err := json.Unmarshal([]byte(encoded), &response); err != nil {
			t.Fatalf("invalid response: %v", err)
		}
		if response.SchemaVersion != SchemaVersion {
			t.Fatalf("unexpected schema %q", response.SchemaVersion)
		}
		if response.OK && (response.Result == nil || response.Result.Verification != "not-performed" || response.Result.TrustAnchor != "not-selected") {
			t.Fatalf("analysis implied trust: %#v", response)
		}
	})
}
