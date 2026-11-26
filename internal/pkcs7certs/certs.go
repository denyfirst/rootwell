// Package pkcs7certs reads a PKCS#7 certificate bundle, the .p7b or .p7c
// file Windows and OpenSSL write: a SignedData that holds certificates and
// nothing else. It signs and verifies nothing, and makes no trust decision.
package pkcs7certs

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"errors"

	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/limits"
)

var (
	// ErrNotPKCS7 is input that is not a PKCS#7 SignedData at all.
	ErrNotPKCS7 = errors.New("input is not a PKCS#7 bundle")
	// ErrUnsupported is a PKCS#7 SignedData that is not a plain DER bundle of
	// 1 to 64 distinct certificates: signed content, signers, revocation
	// lists, attribute certificates, BER encoding or a damaged certificate.
	ErrUnsupported = errors.New("PKCS#7 bundle holds something other than certificates")
)

var (
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	// The DER of the signedData OID, the first field of its ContentInfo.
	signedDataOID = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}
)

// IsPKCS7 reports whether input starts like a PKCS#7 SignedData, in DER or
// BER. It decides how a page treats a file, never whether it is read.
func IsPKCS7(input []byte) bool {
	if len(input) < 2 || input[0] != 0x30 {
		return false
	}
	header := 2
	if length := input[1]; length > 0x80 {
		header += int(length & 0x7f)
	}
	return len(input) >= header+len(signedDataOID) && bytes.Equal(input[header:header+len(signedDataOID)], signedDataOID)
}

// elements splits DER content into its top-level elements.
func elements(content []byte) ([]asn1.RawValue, bool) {
	var out []asn1.RawValue
	for len(content) != 0 {
		var element asn1.RawValue
		rest, err := asn1.Unmarshal(content, &element)
		if err != nil {
			return nil, false
		}
		out = append(out, element)
		content = rest
	}
	return out, true
}

func is(element asn1.RawValue, class, tag int, compound bool) bool {
	return element.Class == class && element.Tag == tag && element.IsCompound == compound
}

// Parse returns copies of the certificates in a certs-only SignedData, in
// file order. Anything it does not understand is refused, never skipped.
func Parse(input []byte) ([][]byte, error) {
	if len(input) == 0 || int64(len(input)) > limits.MaxInputBytes || !IsPKCS7(input) {
		return nil, ErrNotPKCS7
	}
	var outer asn1.RawValue
	if rest, err := asn1.Unmarshal(input, &outer); err != nil || len(rest) != 0 || !is(outer, asn1.ClassUniversal, asn1.TagSequence, true) {
		return nil, ErrUnsupported
	}
	contentInfo, ok := elements(outer.Bytes)
	if !ok || len(contentInfo) != 2 || !is(contentInfo[1], asn1.ClassContextSpecific, 0, true) {
		return nil, ErrUnsupported
	}
	var contentType asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(contentInfo[0].FullBytes, &contentType); err != nil || len(rest) != 0 || !contentType.Equal(oidSignedData) {
		return nil, ErrUnsupported
	}
	wrapped, ok := elements(contentInfo[1].Bytes)
	if !ok || len(wrapped) != 1 || !is(wrapped[0], asn1.ClassUniversal, asn1.TagSequence, true) {
		return nil, ErrUnsupported
	}
	fields, ok := elements(wrapped[0].Bytes)
	if !ok || len(fields) < 4 || len(fields) > 6 {
		return nil, ErrUnsupported
	}
	var version int
	if rest, err := asn1.Unmarshal(fields[0].FullBytes, &version); err != nil || len(rest) != 0 || version != 1 {
		return nil, ErrUnsupported
	}
	// No digest algorithms and no signers: nothing is signed.
	signers := fields[len(fields)-1]
	if !is(fields[1], asn1.ClassUniversal, asn1.TagSet, true) || len(fields[1].Bytes) != 0 ||
		!is(signers, asn1.ClassUniversal, asn1.TagSet, true) || len(signers.Bytes) != 0 {
		return nil, ErrUnsupported
	}
	// The content is "data" and absent.
	content, ok := elements(fields[2].Bytes)
	if !ok || !is(fields[2], asn1.ClassUniversal, asn1.TagSequence, true) || len(content) != 1 {
		return nil, ErrUnsupported
	}
	var dataType asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(content[0].FullBytes, &dataType); err != nil || len(rest) != 0 || !dataType.Equal(oidData) {
		return nil, ErrUnsupported
	}
	optional := fields[3 : len(fields)-1]
	if len(optional) == 0 || !is(optional[0], asn1.ClassContextSpecific, 0, true) {
		return nil, ErrUnsupported
	}
	// No revocation list may hide behind the certificates: none, or the
	// empty set some writers leave.
	if len(optional) == 2 && (!is(optional[1], asn1.ClassContextSpecific, 1, true) || len(optional[1].Bytes) != 0) {
		return nil, ErrUnsupported
	}
	items, ok := elements(optional[0].Bytes)
	if !ok || len(items) == 0 || len(items) > limits.MaxCertificatesPerBundle {
		return nil, ErrUnsupported
	}
	certificates := make([][]byte, 0, len(items))
	seen := make(map[[sha256.Size]byte]bool)
	for _, item := range items {
		// Only the X.509 choice; the tagged choices are extended and
		// attribute certificates.
		if !is(item, asn1.ClassUniversal, asn1.TagSequence, true) {
			return nil, ErrUnsupported
		}
		der := bytes.Clone(item.FullBytes)
		if _, _, err := certinspect.Parse(der); err != nil {
			return nil, ErrUnsupported
		}
		digest := sha256.Sum256(der)
		if seen[digest] {
			return nil, ErrUnsupported
		}
		seen[digest] = true
		certificates = append(certificates, der)
	}
	return certificates, nil
}
