package acmecertificate

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProductionReceiptTrustIsFixedIndependentAndNeverIncludesStaging(t *testing.T) {
	roots, err := productionTrust()
	if err != nil || len(roots) != 2 {
		t.Fatal("official production trust refused", err)
	}
	stage, err := stagingTrust()
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range roots {
		if root.CheckSignatureFrom(root) != nil || strings.Contains(root.Subject.CommonName, "STAGING") {
			t.Fatal("not a production root")
		}
		for _, other := range stage {
			if bytes.Equal(root.Raw, other.Raw) {
				t.Fatal("staging root promoted")
			}
		}
	}
	for _, input := range []string{"", stagingRootPEM, productionRootPEM + stagingRootPEM, productionRootPEM + productionRootPEM, productionRootPEM + "not pem", strings.Repeat("x", maxRootBytes+1)} {
		if got, err := checkedProductionRoots(input); !errors.Is(err, ErrProductionInvalid) || got != nil {
			t.Fatal("unreviewed production trust accepted")
		}
	}
	// A valid but reordered/substituted root bundle is also a changed asset.
	reversed := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: roots[1].Raw})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: roots[0].Raw}))
	if got, err := checkedProductionRoots(reversed); err == nil || got != nil {
		t.Fatal("pin order change ignored")
	}
	if got, err := checkedStagingRoots(productionRootPEM); err == nil || got != nil {
		t.Fatal("production roots entered staging trust")
	}
	if out, err := CheckProduction(nil, nil, nil, nil, time.Now()); !errors.Is(err, ErrProductionInvalid) || !reflect.DeepEqual(out, Result{}) {
		t.Fatal("partial proof on refusal")
	}
}

func TestProductionReceiptUsesAllBindingConstraintsWithoutRuntimeRootOverride(t *testing.T) {
	f := fixture(t, []string{"example.com"})
	result, err := productionReceipt(f.private, f.csr, f.names, f.response, f.at, []*x509.Certificate{f.root})
	if err != nil || result.TestOnly || result.Fingerprint == "" || result.PublicFingerprint == "" || len(result.ChainFingerprints) != 3 {
		t.Fatal("valid private synthetic path refused", err)
	}
	// The synthetic path never becomes acceptable through either fixed entry.
	if out, err := CheckProduction(f.private, f.csr, f.names, f.response, f.at); !errors.Is(err, ErrProductionInvalid) || !reflect.DeepEqual(out, Result{}) {
		t.Fatal("synthetic root entered fixed production checker")
	}
	if out, err := Check(f.private, f.csr, f.names, f.response, f.at); !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(out, Result{}) {
		t.Fatal("synthetic root entered fixed staging checker")
	}
	for name, change := range map[string]func(*receiptFixture){
		"names":          func(v *receiptFixture) { v.names = []string{"other.example.com"} },
		"csr":            func(v *receiptFixture) { v.csr = []byte("unrelated") },
		"key":            func(v *receiptFixture) { v.private = []byte("not a key") },
		"expired":        func(v *receiptFixture) { v.at = v.leafTemplate.NotAfter },
		"duplicate":      func(v *receiptFixture) { v.response = [][]byte{v.response[0], v.response[1], v.response[1]} },
		"missing-issuer": func(v *receiptFixture) { v.response = v.response[:1] },
	} {
		t.Run(name, func(t *testing.T) {
			v := f
			change(&v)
			out, err := productionReceipt(v.private, v.csr, v.names, v.response, v.at, []*x509.Certificate{v.root})
			if !errors.Is(err, ErrProductionInvalid) || !reflect.DeepEqual(out, Result{}) {
				t.Fatal("wrong production evidence accepted", name)
			}
		})
	}
}
