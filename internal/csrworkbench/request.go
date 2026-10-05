// Package csrworkbench builds and checks bounded offline DNS/IP certificate
// requests. A signed CSR or matching certificate is never a trust verdict.
package csrworkbench

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/browserprivateconvert"
	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/certverify"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/limits"
)

const SchemaVersion = "rootwell.browser.csr.v1"
const MaxRequestBytes = 64 << 10

var (
	ErrInvalid  = errors.New("certificate request is invalid or unsupported")
	ErrNames    = errors.New("request names or subject are invalid")
	ErrPassword = errors.New("new key password does not meet policy")
)

// Params deliberately contains no arbitrary extensions, attributes, challenge
// password, CA policy, signing-algorithm override or certificate issuance.
type Params struct {
	DNSNames           []string `json:"dns_names"`
	IPAddresses        []string `json:"ip_addresses"`
	CommonName         string   `json:"common_name"`
	Organization       string   `json:"organization"`
	OrganizationalUnit string   `json:"organizational_unit"`
	Country            string   `json:"country"`
	Locality           string   `json:"locality"`
	Province           string   `json:"province"`
}

type Summary struct {
	InputFormat        string   `json:"input_format"`
	Subject            string   `json:"subject"`
	DNSNames           []string `json:"dns_names"`
	IPAddresses        []string `json:"ip_addresses"`
	Algorithm          string   `json:"algorithm"`
	Bits               int      `json:"bits"`
	Curve              string   `json:"curve"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	SignatureChecked   bool     `json:"signature_checked"`
	RequestFingerprint string   `json:"request_fingerprint"`
	PublicFingerprint  string   `json:"public_fingerprint"`
}

// Output includes only encrypted key material when a new key is generated.
// CSR is public PEM retained by the caller for matching; Bytes is downloaded.
// The caller must clear buffers after use; no persistence is performed here.
type Output struct {
	Bytes    []byte
	Filename string
	Format   string
	CSR      []byte
	Summary  Summary
}

type Comparison struct {
	KeyMatch        bool     `json:"key_match"`
	MissingNames    []string `json:"missing_names"`
	AdditionalNames []string `json:"additional_names"`
	SubjectChanged  bool     `json:"subject_changed"`
	CertificateIsCA bool     `json:"certificate_is_ca"`
	TrustChecked    bool     `json:"trust_checked"`
}

func Generate(algorithm string, params Params, password []byte) (Output, error) {
	if !passwordAllowed(password) {
		return Output{}, ErrPassword
	}
	template, err := template(params)
	if err != nil {
		return Output{}, err
	}
	var key crypto.Signer
	switch algorithm {
	case "rsa-2048":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case "rsa-4096":
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	case "ec-p256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec-p384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ec-p521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return Output{}, ErrInvalid
	}
	if err != nil {
		return Output{}, ErrInvalid
	}
	defer keymatch.ClearParsedKey(key)
	csr, summary, err := sign(template, key)
	if err != nil {
		return Output{}, ErrInvalid
	}
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		clear(plain)
		return Output{}, ErrInvalid
	}
	defer clear(plain)
	encrypted, _, err := browserprivateconvert.ExportEncrypted(plain, summary.PublicFingerprint, password)
	if err != nil {
		clear(encrypted)
		return Output{}, ErrInvalid
	}
	defer clear(encrypted)
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{"encrypted-private-key.pem", encrypted}, {"certificate-request.csr", csr},
	} {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		header.SetMode(0o600) // Extraction tools, not Rootwell, control actual permissions.
		destination, err := writer.CreateHeader(header)
		if err == nil {
			_, err = destination.Write(entry.data)
		}
		if err != nil {
			_ = writer.Close()
			clear(buffer.Bytes())
			return Output{}, ErrInvalid
		}
	}
	if err := writer.Close(); err != nil || buffer.Len() == 0 || buffer.Len() > 256<<10 {
		clear(buffer.Bytes())
		return Output{}, ErrInvalid
	}
	name, err := filename("request-and-key", ".zip")
	if err != nil {
		clear(buffer.Bytes())
		return Output{}, ErrInvalid
	}
	return Output{Bytes: buffer.Bytes(), Filename: name, Format: "zip", CSR: csr, Summary: summary}, nil
}

func FromKey(input, password []byte, params Params, format string) (Output, error) {
	if format != "pem" && format != "der" {
		return Output{}, ErrInvalid
	}
	template, err := template(params)
	if err != nil {
		return Output{}, err
	}
	var csr []byte
	var summary Summary
	err = browserprivateconvert.WithInputKey(input, password, func(parsed any, _ keymatch.Encoding) error {
		signer, ok := parsed.(crypto.Signer)
		if !ok {
			return ErrInvalid
		}
		var err error
		csr, summary, err = sign(template, signer)
		return err
	})
	if err != nil {
		return Output{}, ErrInvalid
	}
	output, err := Convert(csr, summary.RequestFingerprint, format)
	if err != nil {
		return Output{}, err
	}
	return output, nil
}

// sign reparses and checks signature, canonical public key, names and subject
// before emitting a request. It never accepts caller-supplied ASN.1 output.
func sign(template *x509.CertificateRequest, key crypto.Signer) ([]byte, Summary, error) {
	if certverify.CheckPublicKeyPolicy(key.Public()) != nil {
		return nil, Summary{}, ErrInvalid
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, Summary{}, ErrInvalid
	}
	parsed, format, err := parse(der)
	if err != nil {
		return nil, Summary{}, ErrInvalid
	}
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || subtle.ConstantTimeCompare(public, parsed.RawSubjectPublicKeyInfo) != 1 ||
		!slices.Equal(template.DNSNames, parsed.DNSNames) || template.Subject.String() != parsed.Subject.String() ||
		len(template.IPAddresses) != len(parsed.IPAddresses) {
		return nil, Summary{}, ErrInvalid
	}
	for i, address := range template.IPAddresses {
		if !address.Equal(parsed.IPAddresses[i]) {
			return nil, Summary{}, ErrInvalid
		}
	}
	summary, err := summarize(parsed, format)
	if err != nil {
		return nil, Summary{}, ErrInvalid
	}
	summary.InputFormat = "pem"
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), summary, nil
}

func Inspect(input []byte) (Summary, error) {
	request, format, err := parse(input)
	if err != nil {
		return Summary{}, ErrInvalid
	}
	return summarize(request, format)
}

func Convert(input []byte, expected, format string) (Output, error) {
	if format != "pem" && format != "der" {
		return Output{}, ErrInvalid
	}
	request, _, err := parse(input)
	if err != nil || !identity(request.Raw, expected) {
		return Output{}, ErrInvalid
	}
	summary, err := summarize(request, format)
	if err != nil {
		return Output{}, ErrInvalid
	}
	extension := ".csr"
	output := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request.Raw})
	if format == "der" {
		output = bytes.Clone(request.Raw)
		extension = ".der"
	}
	name, err := filename("request", extension)
	if err != nil {
		clear(output)
		return Output{}, ErrInvalid
	}
	return Output{Bytes: output, Filename: name, Format: format,
		CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request.Raw}), Summary: summary}, nil
}

// Match compares identity and literal normalized SAN sets, not hostname
// coverage, issuer signature, chain, time, purpose, revocation or deployment.
func Match(input, certificate []byte, expected string) (Comparison, error) {
	request, _, err := parse(input)
	if err != nil || !identity(request.Raw, expected) || len(certificate) == 0 || len(certificate) > 1<<20 {
		return Comparison{}, ErrInvalid
	}
	cert, _, err := certinspect.Parse(certificate)
	if err != nil || len(cert.DNSNames) > 128 || len(cert.IPAddresses) > 128 {
		return Comparison{}, ErrInvalid
	}
	requestPublic, err := x509.MarshalPKIXPublicKey(request.PublicKey)
	if err != nil {
		return Comparison{}, ErrInvalid
	}
	certPublic, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return Comparison{}, ErrInvalid
	}
	wanted, actual := make(map[string]bool), make(map[string]bool)
	for _, name := range request.DNSNames {
		wanted["DNS: "+strings.ToLower(name)] = true
	}
	for _, address := range request.IPAddresses {
		wanted["IP: "+address.String()] = true
	}
	for _, name := range cert.DNSNames {
		normalized, err := dns(name)
		if err != nil || name != strings.TrimSpace(name) {
			return Comparison{}, ErrInvalid
		}
		actual["DNS: "+normalized] = true
	}
	for _, address := range cert.IPAddresses {
		actual["IP: "+address.String()] = true
	}
	result := Comparison{KeyMatch: subtle.ConstantTimeCompare(requestPublic, certPublic) == 1,
		SubjectChanged: !bytes.Equal(request.RawSubject, cert.RawSubject), CertificateIsCA: cert.IsCA,
		MissingNames: []string{}, AdditionalNames: []string{}}
	for name := range wanted {
		if !actual[name] {
			result.MissingNames = append(result.MissingNames, name)
		}
	}
	for name := range actual {
		if !wanted[name] {
			result.AdditionalNames = append(result.AdditionalNames, name)
		}
	}
	slices.Sort(result.MissingNames)
	slices.Sort(result.AdditionalNames)
	return result, nil
}

func parse(input []byte) (*x509.CertificateRequest, string, error) {
	if len(input) == 0 || len(input) > MaxRequestBytes {
		return nil, "", ErrInvalid
	}
	der := bytes.Clone(input)
	format := "der"
	trimmed := bytes.TrimSpace(input)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		if bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 ||
			(!bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE REQUEST-----")) &&
				!bytes.HasPrefix(trimmed, []byte("-----BEGIN NEW CERTIFICATE REQUEST-----"))) {
			return nil, "", ErrInvalid
		}
		block, rest := pem.Decode(trimmed)
		if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
			(block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
			return nil, "", ErrInvalid
		}
		der, format = block.Bytes, "pem"
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil || request.Version != 0 || !bytes.Equal(request.Raw, der) ||
		strictAttributes(request) != nil || certverify.CheckRequestPolicy(request) != nil {
		return nil, "", ErrInvalid
	}
	if _, err := summarize(request, format); err != nil {
		return nil, "", ErrInvalid
	}
	// Metadata and RSA-size limits precede public-key verification work.
	if request.CheckSignature() != nil {
		return nil, "", ErrInvalid
	}
	return request, format, nil
}

// Standard-library ASN.1 decoding rejects attributes/general names that the
// X.509 convenience parser can silently ignore. No custom ASN.1 is emitted.
func strictAttributes(request *x509.CertificateRequest) error {
	var info struct {
		Version            int
		Subject, PublicKey asn1.RawValue
		Attributes         []asn1.RawValue `asn1:"tag:0"`
	}
	rest, err := asn1.Unmarshal(request.RawTBSCertificateRequest, &info)
	if err != nil || len(rest) != 0 || len(info.Attributes) > 1 {
		return ErrInvalid
	}
	for _, raw := range info.Attributes {
		var attribute struct {
			ID     asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}
		rest, err := asn1.Unmarshal(raw.FullBytes, &attribute)
		if err != nil || len(rest) != 0 || !attribute.ID.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}) || len(attribute.Values) != 1 {
			return ErrInvalid
		}
		var extensions []pkix.Extension
		rest, err = asn1.Unmarshal(attribute.Values[0].FullBytes, &extensions)
		if err != nil || len(rest) != 0 || len(extensions) > 1 {
			return ErrInvalid
		}
		for _, extension := range extensions {
			if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
				return ErrInvalid
			}
			var names []asn1.RawValue
			rest, err = asn1.Unmarshal(extension.Value, &names)
			if err != nil || len(rest) != 0 || len(names) > 40 {
				return ErrInvalid
			}
			for _, name := range names {
				if name.Class != asn1.ClassContextSpecific || name.IsCompound || (name.Tag != 2 && name.Tag != 7) {
					return ErrInvalid
				}
			}
		}
	}
	return nil
}

func summarize(request *x509.CertificateRequest, format string) (Summary, error) {
	if len(request.DNSNames) > 32 || len(request.IPAddresses) > 8 || len(request.EmailAddresses) != 0 || len(request.URIs) != 0 {
		return Summary{}, ErrInvalid
	}
	subject := request.Subject.String()
	if !displayText(subject, 4096) {
		return Summary{}, ErrInvalid
	}
	result := Summary{InputFormat: format, Subject: subject, DNSNames: []string{}, IPAddresses: []string{}, SignatureChecked: true,
		SignatureAlgorithm: request.SignatureAlgorithm.String(), RequestFingerprint: fingerprint(request.Raw), PublicFingerprint: fingerprint(request.RawSubjectPublicKeyInfo)}
	canonical, err := x509.MarshalPKIXPublicKey(request.PublicKey)
	if err != nil {
		return Summary{}, ErrInvalid
	}
	result.PublicFingerprint = fingerprint(canonical)
	seen := make(map[string]bool)
	for _, name := range request.DNSNames {
		normalized, err := dns(name)
		if err != nil || name != strings.TrimSpace(name) || seen["DNS:"+normalized] {
			return Summary{}, ErrInvalid
		}
		seen["DNS:"+normalized] = true
		result.DNSNames = append(result.DNSNames, normalized)
	}
	for _, address := range request.IPAddresses {
		name := address.String()
		if name == "<nil>" || seen["IP:"+name] {
			return Summary{}, ErrInvalid
		}
		seen["IP:"+name] = true
		result.IPAddresses = append(result.IPAddresses, name)
	}
	switch public := request.PublicKey.(type) {
	case *rsa.PublicKey:
		result.Algorithm, result.Bits = "RSA", public.N.BitLen()
		if result.Bits > limits.MaxPrivateKeyBits {
			return Summary{}, ErrInvalid
		}
	case *ecdsa.PublicKey:
		result.Algorithm, result.Bits, result.Curve = "ECDSA", public.Curve.Params().BitSize, public.Curve.Params().Name
	case ed25519.PublicKey:
		result.Algorithm, result.Bits = "Ed25519", len(public)*8
	default:
		return Summary{}, ErrInvalid
	}
	return result, nil
}

func template(params Params) (*x509.CertificateRequest, error) {
	if len(params.DNSNames) > 32 || len(params.IPAddresses) > 8 || len(params.DNSNames)+len(params.IPAddresses) == 0 {
		return nil, ErrNames
	}
	result := &x509.CertificateRequest{}
	seen := make(map[string]bool)
	for _, value := range params.DNSNames {
		name, err := dns(value)
		if err != nil || seen["DNS:"+name] {
			return nil, ErrNames
		}
		seen["DNS:"+name] = true
		result.DNSNames = append(result.DNSNames, name)
	}
	for _, value := range params.IPAddresses {
		if len(value) > 64 {
			return nil, ErrNames
		}
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || address.Zone() != "" {
			return nil, ErrNames
		}
		address = address.Unmap()
		if seen["IP:"+address.String()] {
			return nil, ErrNames
		}
		seen["IP:"+address.String()] = true
		result.IPAddresses = append(result.IPAddresses, address.AsSlice())
	}
	common := params.CommonName
	if common == "" {
		if len(result.DNSNames) > 0 {
			common = result.DNSNames[0]
		} else {
			common = result.IPAddresses[0].String()
		}
	}
	if len(common) > 253 {
		return nil, ErrNames
	}
	common = strings.ToLower(strings.TrimSpace(common))
	if address, err := netip.ParseAddr(common); err == nil {
		common = address.Unmap().String()
	}
	if !seen["DNS:"+common] && !seen["IP:"+common] {
		return nil, ErrNames
	}
	result.Subject.CommonName = common
	for _, field := range []struct {
		value  string
		output *[]string
	}{
		{params.Organization, &result.Subject.Organization}, {params.OrganizationalUnit, &result.Subject.OrganizationalUnit},
		{params.Locality, &result.Subject.Locality}, {params.Province, &result.Subject.Province},
	} {
		if !displayText(field.value, 128) {
			return nil, ErrNames
		}
		if value := strings.TrimSpace(field.value); value != "" {
			*field.output = []string{value}
		}
	}
	if params.Country != "" {
		country := strings.ToUpper(params.Country)
		if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
			return nil, ErrNames
		}
		result.Subject.Country = []string{country}
	}
	return result, nil
}

func dns(value string) (string, error) {
	if len(value) > 253 {
		return "", ErrNames
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", ErrNames
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", ErrNames
	}
	labels := strings.Split(strings.TrimPrefix(value, "*."), ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrNames
		}
		for _, character := range []byte(label) {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", ErrNames
			}
		}
	}
	return value, nil
}

func displayText(value string, maximum int) bool {
	if len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return false
		}
	}
	return true
}
func passwordAllowed(value []byte) bool {
	if len(value) < 20 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
func fingerprint(input []byte) string {
	sum := sha256.Sum256(input)
	parts := make([]string, len(sum))
	for i, value := range sum {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{value}))
	}
	return strings.Join(parts, ":")
}
func identity(input []byte, expected string) bool {
	actual := fingerprint(input)
	return len(expected) == len(actual) && subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}
func filename(kind, extension string) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", ErrInvalid
	}
	return "rootwell-" + kind + "-" + hex.EncodeToString(nonce[:]) + extension, nil
}
