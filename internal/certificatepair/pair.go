// Package certificatepair validates an explicitly supplied certificate and
// optional key for the self-hosted library. It makes no trust decision.
package certificatepair

import (
	"crypto/x509"
	"errors"

	"github.com/denyfirst/rootwell/internal/browserprivateconvert"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

var ErrInvalid = errors.New("certificate or matching private key was not accepted")

// Prepare returns one public record and, if requested, a canonical PKCS#8
// key. Callers own and must clear the returned key; errors never return it.
func Prepare(certificate, keyInput, password []byte, owner, location string) (publicinventory.Record, []byte, error) {
	if len(certificate) == 0 || len(certificate) > 96<<10 || len(keyInput) > 64<<10 || len(password) > 256 || (len(keyInput) == 0 && len(password) != 0) {
		return publicinventory.Record{}, nil, ErrInvalid
	}
	var catalog publicinventory.Catalog
	records, err := catalog.Add(certificate, owner, location)
	if err != nil || len(records) != 1 {
		return publicinventory.Record{}, nil, ErrInvalid
	}
	r := records[0]
	if len(keyInput) == 0 {
		return r, nil, nil
	}
	cert, err := x509.ParseCertificate(r.DER)
	if err != nil || cert.IsCA {
		return publicinventory.Record{}, nil, ErrInvalid
	}
	var canonical []byte
	err = browserprivateconvert.WithInputKey(keyInput, password, func(k any, _ keymatch.Encoding) error {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil || len(der) == 0 || len(der) > 64<<10 {
			clear(der)
			return ErrInvalid
		}
		defer clear(der)
		if err := keymatch.WithMatchedKey(r.DER, der, func(_ *x509.Certificate, _ any) error { return nil }); err != nil {
			return ErrInvalid
		}
		canonical = append([]byte(nil), der...)
		return nil
	})
	if err != nil {
		clear(canonical)
		if errors.Is(err, browserprivateconvert.ErrInputPasswordRequired) {
			return publicinventory.Record{}, nil, browserprivateconvert.ErrInputPasswordRequired
		}
		return publicinventory.Record{}, nil, ErrInvalid
	}
	r.HasPrivateKey = true
	return r, canonical, nil
}
