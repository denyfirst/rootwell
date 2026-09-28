// Package publicconvert converts exactly one public X.509 certificate.
// It does not accept bundles, PFX, or private keys and makes no trust claim.
package publicconvert

import (
	"bytes"
	"encoding/pem"
	"errors"

	"github.com/denyfirst/rootwell/internal/certinspect"
)

var ErrInvalidInput = errors.New("invalid public certificate")

// Convert parses one strict certificate and emits its identical DER object in
// the requested encoding. The caller owns the returned bytes.
func Convert(input []byte, to string) ([]byte, error) {
	if to != "pem" && to != "der" {
		return nil, ErrInvalidInput
	}
	certificate, _, err := certinspect.Parse(input)
	if err != nil {
		return nil, ErrInvalidInput
	}
	var output []byte
	if to == "pem" {
		output = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	} else {
		output = bytes.Clone(certificate.Raw)
	}
	if len(output) == 0 {
		return nil, ErrInvalidInput
	}
	reparsed, _, err := certinspect.Parse(output)
	if err != nil || !bytes.Equal(reparsed.Raw, certificate.Raw) {
		clear(output)
		return nil, ErrInvalidInput
	}
	return output, nil
}
