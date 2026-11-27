package csrworkbench

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"testing"
)

// A key Rootwell keeps comes out in the clear, as PKCS #8, only to be sealed
// at once; its request is checked exactly as the browser's.
func TestGenerateKeptChecksLikeTheBrowser(t *testing.T) {
	for _, algorithm := range []string{"ec-p256", "rsa-2048"} {
		csr, key, summary, err := GenerateKept(algorithm, Params{DNSNames: []string{"Shop.Test", "*.shop.test"}, IPAddresses: []string{"192.0.2.7"}, Organization: "Synthetic Shop", Country: "de"})
		if err != nil {
			t.Fatalf("%s: %v", algorithm, err)
		}
		block, rest := pem.Decode(csr)
		if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
			t.Fatalf("%s: the request is not one PEM block", algorithm)
		}
		request, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || request.CheckSignature() != nil {
			t.Fatalf("%s: the request does not verify: %v", algorithm, err)
		}
		if !slices.Equal(request.DNSNames, []string{"shop.test", "*.shop.test"}) || len(request.IPAddresses) != 1 ||
			request.Subject.CommonName != "shop.test" || request.Subject.Country[0] != "DE" || summary.PublicFingerprint == "" {
			t.Fatalf("%s: the request holds %v %v %v", algorithm, request.DNSNames, request.IPAddresses, request.Subject)
		}
		private, err := x509.ParsePKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("%s: the key is not PKCS #8: %v", algorithm, err)
		}
		own, _ := x509.MarshalPKIXPublicKey(private.(crypto.Signer).Public())
		if string(own) != string(request.RawSubjectPublicKeyInfo) {
			t.Fatalf("%s: the key is not the request's own", algorithm)
		}
		clear(key)
	}
	for _, tc := range []struct {
		algorithm string
		params    Params
		want      error
	}{
		{"dsa-1024", Params{DNSNames: []string{"shop.test"}}, ErrInvalid},
		{"ec-p256", Params{}, ErrNames},
		{"ec-p256", Params{DNSNames: []string{"not a name"}}, ErrNames},
		{"ec-p256", Params{DNSNames: []string{"192.0.2.7"}}, ErrNames},
		{"ec-p256", Params{DNSNames: []string{"shop.test"}, Country: "Germany"}, ErrNames},
	} {
		if csr, key, _, err := GenerateKept(tc.algorithm, tc.params); !errors.Is(err, tc.want) || csr != nil || key != nil {
			t.Fatalf("%s %+v: %v", tc.algorithm, tc.params, err)
		}
	}
}
