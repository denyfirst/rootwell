package renewalpolicy

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
)

// CertificateID is RFC 9773's public identifier, not issuer trust or ownership.
// Standard ASN.1 encoding preserves the positive INTEGER's necessary leading
// zero. No hand-written DER encoder or caller-controlled URL is used.
func CertificateID(der []byte) (string, error) {
	if len(der) == 0 || len(der) > 64<<10 {
		return "", ErrInvalid
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || cert.IsCA || len(cert.AuthorityKeyId) == 0 || len(cert.AuthorityKeyId) > 64 || cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 160 {
		return "", ErrInvalid
	}
	encoded, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return "", ErrInvalid
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(encoded, &raw)
	if err != nil || len(rest) != 0 || raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagInteger || raw.IsCompound || len(raw.Bytes) == 0 || len(raw.Bytes) > 20 {
		return "", ErrInvalid
	}
	return base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(raw.Bytes), nil
}
