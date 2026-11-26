package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/publicinventory"
)

// The list shows each certificate's IP names, key type and issuers, read from
// its own public certificates; nothing else enters these fields.
func TestTheListShowsIPNamesKeyTypeAndIssuers(t *testing.T) {
	now := time.Now()
	serial := int64(0)
	mint := func(name string, pub crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer, ca bool) *x509.Certificate {
		serial++
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name, Organization: []string{"Lab"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: ca}
		if !ca {
			tmpl.IPAddresses = []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("fd00::5")}
		}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	rootPub, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	root := mint("Lab Root", rootPub, nil, rootKey, true)
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	issuer := mint("Lab Issuing CA", issuerKey.Public(), root, rootKey, true)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		key  crypto.PublicKey
		want string
	}{{rsaKey.Public(), "RSA 2048"}, {ecKey.Public(), "ECDSA P-256"}, {edPub, "Ed25519"}} {
		want := tc.want
		leaf := mint("nas.lab", tc.key, issuer, issuerKey, false)
		ips, keyType, chain := certificateFacts(publicinventory.Record{DER: leaf.Raw, IssuerDER: [][]byte{issuer.Raw, root.Raw}})
		if keyType != want || !slices.Equal(ips, []string{"10.0.0.5", "fd00::5"}) || len(chain) != 2 ||
			!strings.Contains(chain[0].Subject, "Lab Issuing CA") || chain[0].Root || !chain[1].Root || !strings.Contains(chain[1].Issuer, "Lab Root") {
			t.Fatalf("%s: %v %q %+v", want, ips, keyType, chain)
		}
	}
	// A record whose certificate cannot be read shows nothing, never a guess.
	ips, keyType, chain := certificateFacts(publicinventory.Record{DER: []byte{0x30, 0x00}, IssuerDER: [][]byte{issuer.Raw}})
	if len(ips) != 0 || keyType != "" || len(chain) != 0 || ips == nil || chain == nil {
		t.Fatal("an unreadable certificate produced facts")
	}
}
