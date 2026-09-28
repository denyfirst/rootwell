package publicinventory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/publicbundle"
)

func demo(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile("../../web/workbench/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestImportPublicCertificateAndDetachResults(t *testing.T) {
	input := demo(t, "rootwell-demo-certificate.pem")
	var c Catalog
	added, err := c.Add(input, "Platform team", "production/nginx")
	if err != nil || len(added) != 1 {
		t.Fatalf("public import: %v, count %d", err, len(added))
	}
	if added[0].Fingerprint == "" || added[0].Subject == "" || added[0].NotBefore == "" || added[0].NotAfter == "" ||
		added[0].Owner != "Platform team" || added[0].Location != "production/nginx" || len(added[0].DER) == 0 {
		t.Fatalf("incomplete public record: %+v", added[0])
	}
	originalDER := bytes.Clone(added[0].DER)
	originalDNS := slices.Clone(added[0].DNSNames)
	originalLocations := slices.Clone(added[0].Locations)
	input[0] = 'x'
	added[0].DER[0] = 0
	added[0].Locations[0] = "mutated/location"
	if len(added[0].DNSNames) > 0 {
		added[0].DNSNames[0] = "mutated.invalid"
	}
	listed := c.List()
	if len(listed) != 1 || !bytes.Equal(listed[0].DER, originalDER) || !slices.Equal(listed[0].DNSNames, originalDNS) || !slices.Equal(listed[0].Locations, originalLocations) {
		t.Fatal("caller mutated the catalog through input or return value")
	}
	listed[0].DER[0] = 0
	listed[0].Locations[0] = "mutated/again"
	if len(listed[0].DNSNames) > 0 {
		listed[0].DNSNames[0] = "mutated.invalid"
	}
	if !bytes.Equal(c.List()[0].DER, originalDER) || !slices.Equal(c.List()[0].DNSNames, originalDNS) || !slices.Equal(c.List()[0].Locations, originalLocations) {
		t.Fatal("caller mutated the catalog through List")
	}
}

func TestAssociateLocationIsBoundedExplicitAndDetached(t *testing.T) {
	var c Catalog
	added, err := c.Add(demo(t, "rootwell-demo-certificate.pem"), "Platform", "production/nginx")
	if err != nil {
		t.Fatal(err)
	}
	second, err := AssociateLocation(added[0], "production/haproxy")
	if err != nil || second.Location != "production/nginx" || !slices.Equal(second.Locations, []string{"production/nginx", "production/haproxy"}) {
		t.Fatalf("second location: %v %#v", err, second.Locations)
	}
	second.Locations[0] = "mutated"
	if added[0].Locations[0] != "production/nginx" || c.List()[0].Locations[0] != "production/nginx" {
		t.Fatal("association mutated its source")
	}
	second.Locations[0] = "production/nginx"
	for _, location := range []string{"", " bad", "bad\nlocation", strings.Repeat("x", maxLabel+1)} {
		if result, err := AssociateLocation(second, location); !errors.Is(err, ErrLabel) || result.Fingerprint != "" {
			t.Fatalf("invalid location accepted: %q %v", location, err)
		}
	}
	if result, err := AssociateLocation(second, "production/haproxy"); !errors.Is(err, ErrLocationDuplicate) || result.Fingerprint != "" {
		t.Fatalf("duplicate location accepted: %v", err)
	}
	for len(second.Locations) < maxLocations {
		second, err = AssociateLocation(second, "host/"+strings.Repeat("x", len(second.Locations)))
		if err != nil {
			t.Fatal(err)
		}
	}
	if result, err := AssociateLocation(second, "one-too-many"); !errors.Is(err, ErrLocationCapacity) || result.Fingerprint != "" {
		t.Fatalf("location cap bypassed: %v", err)
	}
	unknown, err := c.Add(demo(t, "rootwell-verify-demo-root.pem"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := AssociateLocation(unknown[0], "new/first")
	if err != nil || first.Location != "new/first" || !slices.Equal(first.Locations, []string{"new/first"}) {
		t.Fatalf("unknown first location: %v", err)
	}
}

func TestDuplicateAndMalformedImportsAreAtomic(t *testing.T) {
	leaf := demo(t, "rootwell-demo-certificate.pem")
	root := demo(t, "rootwell-verify-demo-root.pem")
	var c Catalog
	if _, err := c.Add(leaf, "", ""); err != nil {
		t.Fatal(err)
	}
	parsed, err := publicbundle.Parse(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Add(parsed[0].DER, "", ""); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("same certificate in DER was not a duplicate: %v", err)
	}
	if _, err := c.Add(append(bytes.Clone(root), leaf...), "", ""); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("cross-import duplicate accepted: %v", err)
	}
	if len(c.List()) != 1 {
		t.Fatal("duplicate batch partially changed catalog")
	}
	for _, input := range [][]byte{
		[]byte("not a certificate"),
		[]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
		append(bytes.Clone(root), []byte("trailing garbage")...),
		bytes.Repeat([]byte("x"), 16<<20+1),
	} {
		if _, err := c.Add(input, "", ""); err == nil {
			t.Fatal("malformed or secret-bearing input accepted")
		}
		if len(c.List()) != 1 {
			t.Fatal("rejected input changed catalog")
		}
	}
	if _, err := c.Add(root, "", ""); err != nil {
		t.Fatalf("valid import after rejection failed: %v", err)
	}
}

func TestOversizedSingleCertificateIsRejectedWithoutMutation(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "oversized test certificate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: bytes.Repeat([]byte{0x41}, maxDERBytes)}},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	if len(der) <= maxDERBytes {
		t.Fatal("test certificate did not exceed the inventory bound")
	}
	var c Catalog
	if _, err := c.Add(der, "", ""); !errors.Is(err, ErrCertSize) || len(c.List()) != 0 {
		t.Fatalf("oversized certificate was accepted or stored: %v", err)
	}
}

func TestLabelsAndCapacityFailClosed(t *testing.T) {
	input := demo(t, "rootwell-demo-certificate.pem")
	for _, label := range []string{" leading", "trailing ", "bad\nline", "bad\u2028line", "bidirectional\u202e", string([]byte{0xff}), strings.Repeat("x", maxLabel+1)} {
		var c Catalog
		if _, err := c.Add(input, label, ""); !errors.Is(err, ErrLabel) || len(c.List()) != 0 {
			t.Fatalf("bad label accepted or stored: %q, %v", label, err)
		}
	}
	var c Catalog
	c.records = make([]Record, maxRecords)
	if _, err := c.Add(input, "", ""); !errors.Is(err, ErrCapacity) || len(c.List()) != maxRecords {
		t.Fatalf("full catalog accepted more records: %v", err)
	}
}

func TestConcurrentDuplicateImportHasOneWinner(t *testing.T) {
	input := demo(t, "rootwell-demo-certificate.pem")
	var c Catalog
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.Add(input, "", "")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, duplicate := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrDuplicate):
			duplicate++
		default:
			t.Fatalf("unexpected import error: %v", err)
		}
	}
	if success != 1 || duplicate != 7 || len(c.List()) != 1 {
		t.Fatalf("duplicate race: successes %d, duplicates %d, records %d", success, duplicate, len(c.List()))
	}
}

func TestBundledPublicCertificatesRemainUnverified(t *testing.T) {
	input := demo(t, "rootwell-verify-demo-ca-files.pem")
	entries, err := publicbundle.Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	var c Catalog
	added, err := c.Add(input, "", "")
	if err != nil || len(added) != len(entries) {
		t.Fatalf("bundle import: %v, count %d", err, len(added))
	}
	for _, record := range added {
		if record.Fingerprint == "" || record.Owner != "" || record.Location != "" {
			t.Fatal("public inventory record lost unknown fields or fingerprint")
		}
	}
}
