package certificatepair

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/denyfirst/rootwell/internal/browserprivateconvert"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

const MaxBundleBytes = 768 << 10
const MaxBundleCertificates = 16
const MaxBundleDERBytes = 512 << 10

// SelectionRequired contains public candidates only. No candidate is silently
// discarded, and a preview grants no authority to save.
type SelectionRequired struct{ Candidates []publicinventory.Record }

func (*SelectionRequired) Error() string { return "choose the primary certificate" }

// Analyze compares a bounded public collection with a strict optional key.
// It returns no private bytes. Mismatch is a successful comparison, not a
// parsing/password error and not a certificate-trust verdict.
func Analyze(input, key, password []byte) ([]publicinventory.Record, error) {
	records, canonical, err := analyze(input, key, password, "", "")
	clear(canonical)
	return records, err
}

func analyze(input, key, password []byte, owner, location string) ([]publicinventory.Record, []byte, error) {
	if len(input) == 0 || len(input) > MaxBundleBytes || len(key) > 64<<10 || len(password) > 256 || (len(key) == 0 && len(password) != 0) {
		return nil, nil, ErrInvalid
	}
	var catalog publicinventory.Catalog
	records, err := catalog.Add(input, owner, location)
	if err != nil || len(records) == 0 || len(records) > MaxBundleCertificates {
		return nil, nil, ErrInvalid
	}
	totalDER := 0
	for i := range records {
		totalDER += len(records[i].DER)
		records[i].KeyStatus = "not-added"
	}
	if totalDER > MaxBundleDERBytes {
		return nil, nil, ErrInvalid
	}
	if len(key) == 0 {
		return records, nil, nil
	}
	var canonical []byte
	err = browserprivateconvert.WithInputKey(key, password, func(k any, _ keymatch.Encoding) error {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		defer clear(der)
		if err != nil || len(der) == 0 || len(der) > 64<<10 {
			return ErrInvalid
		}
		for i := range records {
			result, err := keymatch.Match(records[i].DER, der)
			if err != nil {
				return ErrInvalid
			}
			records[i].HasPrivateKey = true
			records[i].KeyStatus = "mismatch"
			if result.Match {
				records[i].KeyStatus = "matched"
			}
		}
		canonical = bytes.Clone(der)
		return nil
	})
	if err != nil {
		clear(canonical)
		if errors.Is(err, browserprivateconvert.ErrInputPasswordRequired) {
			return nil, nil, browserprivateconvert.ErrInputPasswordRequired
		}
		return nil, nil, ErrInvalid
	}
	return records, canonical, nil
}

// PrepareBundle selects one primary record while preserving all supplied public
// certificates. Issuer signatures are checked, but no included root is trusted.
// Unrelated, ambiguous, cyclic or name-only issuer collections are refused.
// A valid unrelated key may be retained only with explicit acknowledgement by
// the writer; callers receive its computed status, never a client-supplied one.
func PrepareBundle(input, key, password []byte, owner, location, selected string) (publicinventory.Record, []byte, error) {
	records, canonical, err := analyze(input, key, password, owner, location)
	if err != nil {
		return publicinventory.Record{}, nil, err
	}
	ok := false
	defer func() {
		if !ok {
			clear(canonical)
		}
	}()
	certs := make([]*x509.Certificate, len(records))
	var candidates, matching []publicinventory.Record
	for i, r := range records {
		certs[i], err = x509.ParseCertificate(r.DER)
		if err != nil {
			return publicinventory.Record{}, nil, ErrInvalid
		}
		if len(key) != 0 && certs[i].IsCA && r.KeyStatus == "matched" {
			return publicinventory.Record{}, nil, ErrInvalid
		}
		if !certs[i].IsCA {
			candidates = append(candidates, r)
			if r.KeyStatus == "matched" {
				matching = append(matching, r)
			}
		}
	}
	if len(candidates) == 0 {
		candidates = records
	}
	if selected == "" {
		choices := candidates
		if len(matching) != 0 {
			choices = matching
		}
		if len(choices) != 1 {
			return publicinventory.Record{}, nil, &SelectionRequired{Candidates: choices}
		}
		selected = choices[0].Fingerprint
	}
	index := -1
	for i, r := range records {
		if r.Fingerprint == selected {
			index = i
		}
	}
	if index < 0 || (len(key) != 0 && certs[index].IsCA) {
		return publicinventory.Record{}, nil, ErrInvalid
	}
	r := records[index]
	seen := map[int]bool{index: true}
	current := index
	for {
		child := certs[current]
		if bytes.Equal(child.RawIssuer, child.RawSubject) && child.CheckSignatureFrom(child) == nil {
			break
		}
		parent := -1
		for i, candidate := range certs {
			if i == current || !bytes.Equal(child.RawIssuer, candidate.RawSubject) || child.CheckSignatureFrom(candidate) != nil {
				continue
			}
			if parent != -1 {
				return publicinventory.Record{}, nil, ErrInvalid
			}
			parent = i
		}
		if parent == -1 {
			break
		} // partial chain; no trust claim
		if seen[parent] {
			return publicinventory.Record{}, nil, ErrInvalid
		}
		seen[parent] = true
		r.IssuerDER = append(r.IssuerDER, bytes.Clone(records[parent].DER))
		current = parent
	}
	for i, cert := range certs {
		if !seen[i] && (cert.IsCA || !bytes.Equal(cert.RawSubjectPublicKeyInfo, certs[index].RawSubjectPublicKeyInfo) || !bytes.Equal(cert.RawIssuer, certs[index].RawIssuer)) {
			return publicinventory.Record{}, nil, ErrInvalid
		}
		if !seen[i] {
			for j, issuer := range certs {
				if i != j && issuer.IsCA && bytes.Equal(cert.RawIssuer, issuer.RawSubject) && cert.CheckSignatureFrom(issuer) != nil {
					return publicinventory.Record{}, nil, ErrInvalid
				}
			}
		}
		r.BundleDER = append(r.BundleDER, bytes.Clone(records[i].DER))
	}
	ok = true
	return r, canonical, nil
}

// PublicPEM reconstructs only public CERTIFICATE blocks; passwords, file names
// and unknown input bytes are never retained as attachments.
func PublicPEM(certificates [][]byte) []byte {
	var out []byte
	for _, der := range certificates {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}
