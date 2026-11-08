// Package browserpfximport prepares an authenticated PFX for the existing
// certificate library API. Only public certificates and a newly encrypted key
// leave the one-shot browser worker. It has no storage or network capability.
package browserpfximport

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"

	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/pfxinspect"
	"github.com/denyfirst/rootwell/internal/pfxkeyexport"
)

const Schema = "rootwell.browser.pfx-import.v1"

var ErrInvalid = errors.New("PFX import preparation failed")

type Prepared struct {
	Certificate []byte
	PrivateKey  []byte
	KeyPassword []byte
	Fingerprint string
}

func (p *Prepared) Clear() {
	clear(p.Certificate)
	clear(p.PrivateKey)
	clear(p.KeyPassword)
}

// Prepare accepts the existing bounded modern profile, never a new PKCS#12
// dialect. Supplied roots remain public material, not trust. The raw PFX and
// its password must not be uploaded or persisted as library data.
func Prepare(input, password []byte) (prepared Prepared, err error) {
	if len(input) == 0 || len(input) > 1<<20 || len(password) == 0 || len(password) > 128 {
		return Prepared{}, ErrInvalid
	}
	bound := bytes.Clone(input)
	defer clear(bound)
	good := false
	defer func() {
		if !good {
			prepared.Clear()
			prepared = Prepared{}
		}
	}()
	summary, err := pfxinspect.Inspect(bound, string(password))
	if err != nil {
		return prepared, ErrInvalid
	}
	prepared.Fingerprint = summary.MatchingCertificate.SHA256Fingerprint
	var certificates [][]byte
	for _, report := range append([]string{prepared.Fingerprint}, fingerprints(summary)...) {
		der, ok := summary.CertificateDER(report)
		if !ok {
			return prepared, ErrInvalid
		}
		certificates = append(certificates, der)
	}
	prepared.Certificate = certificatepair.PublicPEM(certificates)
	for _, der := range certificates {
		clear(der)
	}
	// Do not silently discard unrelated CAs or other leaves from a container.
	// Reuse the same chain/primary policy that the server will enforce again.
	record, canonical, err := certificatepair.PrepareBundle(prepared.Certificate, nil, nil, "", "", prepared.Fingerprint)
	clear(canonical)
	if err != nil || record.Fingerprint != prepared.Fingerprint || len(record.BundleDER) != len(certificates) {
		return prepared, ErrInvalid
	}
	var entropy [32]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return prepared, ErrInvalid
	}
	defer clear(entropy[:])
	prepared.KeyPassword = make([]byte, base64.RawURLEncoding.EncodedLen(len(entropy)))
	base64.RawURLEncoding.Encode(prepared.KeyPassword, entropy[:])
	if len(password) == len(prepared.KeyPassword) && subtle.ConstantTimeCompare(password, prepared.KeyPassword) == 1 {
		return prepared, ErrInvalid
	}
	prepared.PrivateKey, err = pfxkeyexport.Export(bound, string(password), prepared.Fingerprint, prepared.KeyPassword)
	if err != nil || len(prepared.PrivateKey) == 0 || len(prepared.PrivateKey) > 64<<10 {
		return prepared, ErrInvalid
	}
	good = true
	return prepared, nil
}

func fingerprints(summary pfxinspect.Result) []string {
	result := make([]string, 0, len(summary.Additional))
	for _, cert := range summary.Additional {
		result = append(result, cert.SHA256Fingerprint)
	}
	return result
}
