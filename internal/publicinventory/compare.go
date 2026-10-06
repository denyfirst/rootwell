package publicinventory

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/denyfirst/rootwell/internal/publicbundle"
)

// Comparison is public metadata, never a trust, deployment or renewal verdict.
type Comparison struct {
	OldFingerprint  string   `json:"old_fingerprint"`
	NewFingerprint  string   `json:"new_fingerprint"`
	SameCertificate bool     `json:"same_certificate"`
	SamePublicKey   bool     `json:"same_public_key"`
	SubjectChanged  bool     `json:"subject_changed"`
	IssuerChanged   bool     `json:"issuer_changed"`
	AddedNames      []string `json:"added_names"`
	RemovedNames    []string `json:"removed_names"`
	OldExpiry       string   `json:"old_expiry"`
	NewExpiry       string   `json:"new_expiry"`
	ExpiryExtended  bool     `json:"expiry_extended"`
	ValidityChanged bool     `json:"validity_changed"`
	Verification    string   `json:"verification"`
}

func singlePublic(input []byte) (*x509.Certificate, string, error) {
	if len(input) < 1 || len(input) > 96<<10 {
		return nil, "", errors.New("single public certificate required")
	}
	entries, err := publicbundle.Parse(input)
	if err != nil || len(entries) != 1 || len(entries[0].DER) > maxDERBytes {
		return nil, "", errors.New("single public certificate required")
	}
	cert, err := x509.ParseCertificate(entries[0].DER)
	if err != nil {
		return nil, "", errors.New("single public certificate required")
	}
	return cert, entries[0].Inspection.SHA256Fingerprint, nil
}

func Compare(oldInput, newInput []byte) (Comparison, error) {
	a, oldID, err := singlePublic(oldInput)
	if err != nil {
		return Comparison{}, err
	}
	b, newID, err := singlePublic(newInput)
	if err != nil {
		return Comparison{}, err
	}
	names := func(c *x509.Certificate) []string {
		values := []string{}
		for _, value := range c.DNSNames {
			values = append(values, "DNS:"+strings.ToLower(value))
		}
		for _, value := range c.IPAddresses {
			values = append(values, "IP:"+value.String())
		}
		for _, value := range c.EmailAddresses {
			values = append(values, "Email:"+value)
		}
		for _, value := range c.URIs {
			values = append(values, "URI:"+value.String())
		}
		slices.Sort(values)
		return slices.Compact(values)
	}
	oldNames, newNames := names(a), names(b)
	added, removed := []string{}, []string{}
	for _, value := range newNames {
		if _, present := slices.BinarySearch(oldNames, value); !present {
			added = append(added, value)
		}
	}
	for _, value := range oldNames {
		if _, present := slices.BinarySearch(newNames, value); !present {
			removed = append(removed, value)
		}
	}
	return Comparison{OldFingerprint: oldID, NewFingerprint: newID, SameCertificate: bytes.Equal(a.Raw, b.Raw), SamePublicKey: bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo),
		SubjectChanged: !bytes.Equal(a.RawSubject, b.RawSubject), IssuerChanged: !bytes.Equal(a.RawIssuer, b.RawIssuer), AddedNames: added, RemovedNames: removed,
		OldExpiry: a.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), NewExpiry: b.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), ExpiryExtended: b.NotAfter.After(a.NotAfter),
		ValidityChanged: !a.NotBefore.Equal(b.NotBefore) || !a.NotAfter.Equal(b.NotAfter), Verification: "not-performed"}, nil
}

// CompareJSON is the bounded WASM public boundary, with no input reflection.
func CompareJSON(oldInput, newInput []byte) string {
	result, err := Compare(oldInput, newInput)
	var output struct {
		Schema string      `json:"schema_version"`
		OK     bool        `json:"ok"`
		Result *Comparison `json:"result"`
		Error  *string     `json:"error"`
	}
	output.Schema = "rootwell.public-comparison.v1"
	if err != nil {
		message := "Choose exactly one supported public certificate on each side."
		output.Error = &message
	} else {
		output.OK = true
		output.Result = &result
	}
	encoded, _ := json.Marshal(output)
	return string(encoded)
}

func ValidFingerprint(value string) bool {
	if len(value) != 95 || strings.ToUpper(value) != value {
		return false
	}
	for i := 2; i < len(value); i += 3 {
		if value[i] != ':' {
			return false
		}
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(value, ":", ""))
	return err == nil && len(raw) == 32
}
