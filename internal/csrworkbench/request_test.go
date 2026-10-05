package csrworkbench

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/rootwell/internal/browserprivateconvert"
	"github.com/denyfirst/rootwell/internal/certverify"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/youmark/pkcs8"
)

const syntheticPassword = "synthetic-CSR-key-password-2026-52eb"

func params() Params {
	return Params{DNSNames: []string{"demo.rootwell.invalid", "www.demo.rootwell.invalid"}, IPAddresses: []string{"192.0.2.10", "2001:db8::10"}, Organization: "Synthetic test only", Country: "az"}
}

func existing(t testing.TB) (crypto.Signer, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(plain); keymatch.ClearParsedKey(key) })
	return key, plain
}

func TestGenerateEncryptedKeyAndSignedCSR(t *testing.T) {
	for _, algorithm := range []string{"rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384", "ec-p521"} {
		t.Run(algorithm, func(t *testing.T) {
			output, err := Generate(algorithm, params(), []byte(syntheticPassword))
			if err != nil {
				t.Fatal(err)
			}
			defer clear(output.Bytes)
			if output.Format != "zip" || !strings.HasSuffix(output.Filename, ".zip") || !output.Summary.SignatureChecked {
				t.Fatal("generation did not produce signed request package")
			}
			reader, err := zip.NewReader(bytes.NewReader(output.Bytes), int64(len(output.Bytes)))
			if err != nil || len(reader.File) != 2 {
				t.Fatal("request/key archive invalid")
			}
			for _, file := range reader.File {
				if file.Method != zip.Store || file.Mode().Perm() != 0o600 || file.UncompressedSize64 > 96<<10 {
					t.Fatal("unsafe archive entry")
				}
				stream, err := file.Open()
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(io.LimitReader(stream, 96<<10+1))
				_ = stream.Close()
				if err != nil {
					t.Fatal(err)
				}
				defer clear(data)
				switch file.Name {
				case "certificate-request.csr":
					summary, err := Inspect(data)
					if err != nil || !bytes.Equal(data, output.CSR) || summary.PublicFingerprint != output.Summary.PublicFingerprint || len(summary.DNSNames) != 2 || len(summary.IPAddresses) != 2 {
						t.Fatal("CSR did not preserve requested identity/names")
					}
					if bytes.Contains(data, []byte("PRIVATE KEY")) {
						t.Fatal("CSR contains private key")
					}
				case "encrypted-private-key.pem":
					if !bytes.HasPrefix(data, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) || bytes.Contains(data, []byte(syntheticPassword)) {
						t.Fatal("new key was not protected")
					}
					summary, err := browserprivateconvert.InspectWithPassword(data, []byte(syntheticPassword))
					if err != nil || summary.PublicFingerprint != output.Summary.PublicFingerprint {
						t.Fatal("new key does not match CSR")
					}
					if _, err := browserprivateconvert.InspectWithPassword(data, []byte("wrong")); err == nil {
						t.Fatal("wrong password unlocked generated key")
					}
				default:
					t.Fatal("unexpected archive entry")
				}
			}
		})
	}
}

func TestExistingKeyCSRFormatsAndEncryptedInput(t *testing.T) {
	key, plain := existing(t)
	encrypted, err := pkcs8.MarshalPrivateKey(key, []byte(syntheticPassword), &pkcs8.Opts{Cipher: pkcs8.AES256CBC, KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: 1000, HMACHash: crypto.SHA256}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encrypted)
	for _, source := range []struct {
		name           string
		data, password []byte
	}{
		{"plain-der", plain, nil}, {"plain-pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: plain}), nil},
		{"encrypted-der", encrypted, []byte(syntheticPassword)}, {"encrypted-pem", pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encrypted}), []byte(syntheticPassword)},
	} {
		for _, format := range []string{"pem", "der"} {
			t.Run(source.name+"/"+format, func(t *testing.T) {
				output, err := FromKey(source.data, source.password, params(), format)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(output.Bytes)
				summary, err := Inspect(output.Bytes)
				if err != nil || !summary.SignatureChecked || summary.InputFormat != format || summary.PublicFingerprint != output.Summary.PublicFingerprint {
					t.Fatal("existing-key CSR round trip failed")
				}
				for _, target := range []string{"pem", "der"} {
					converted, err := Convert(output.Bytes, summary.RequestFingerprint, target)
					if err != nil {
						t.Fatal(err)
					}
					again, err := Inspect(converted.Bytes)
					clear(converted.Bytes)
					if err != nil || again.RequestFingerprint != summary.RequestFingerprint {
						t.Fatal("CSR conversion changed signed request")
					}
				}
			})
		}
	}
	for _, password := range [][]byte{nil, []byte("wrong")} {
		output, err := FromKey(encrypted, password, params(), "pem")
		if err != ErrInvalid || len(output.Bytes) != 0 {
			t.Fatal("unauthenticated key produced CSR")
		}
	}
	if output, err := FromKey(plain, []byte(syntheticPassword), params(), "pem"); err != ErrInvalid || len(output.Bytes) != 0 {
		t.Fatal("unexpected password on plaintext accepted")
	}
}

func certificate(t *testing.T, key crypto.Signer, request *x509.CertificateRequest, change bool) []byte {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: request.Subject, DNSNames: request.DNSNames, IPAddresses: request.IPAddresses,
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour), BasicConstraintsValid: true}
	if change {
		template.DNSNames = []string{"demo.rootwell.invalid", "extra.rootwell.invalid"}
		template.Subject.CommonName = "changed.rootwell.invalid"
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestReturnedCertificateComparisonDoesNotImplyTrust(t *testing.T) {
	key, plain := existing(t)
	output, err := FromKey(plain, nil, params(), "der")
	if err != nil {
		t.Fatal(err)
	}
	request, err := x509.ParseCertificateRequest(output.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cert := certificate(t, key, request, false)
	match, err := Match(output.Bytes, cert, output.Summary.RequestFingerprint)
	if err != nil || !match.KeyMatch || len(match.MissingNames) != 0 || len(match.AdditionalNames) != 0 || match.SubjectChanged || match.TrustChecked {
		t.Fatal("same expired self-signed certificate comparison wrong or implied trust")
	}
	match, err = Match(output.Bytes, certificate(t, key, request, true), output.Summary.RequestFingerprint)
	if err != nil || !match.KeyMatch || !match.SubjectChanged || !match.CertificateIsCA || match.TrustChecked || len(match.MissingNames) != 1 || len(match.AdditionalNames) != 1 {
		t.Fatal("changed names/subject/CA status hidden")
	}
	other, _ := existing(t)
	match, err = Match(output.Bytes, certificate(t, other, request, false), output.Summary.RequestFingerprint)
	if err != nil || match.KeyMatch || match.TrustChecked {
		t.Fatal("different public key accepted")
	}
	if _, err := Match(output.Bytes, cert, strings.Repeat("AA:", 31)+"AA"); err != ErrInvalid {
		t.Fatal("stale request fingerprint accepted")
	}
}

func TestCSRRefusesMalformedUnsafeAndIgnoredFields(t *testing.T) {
	key, plain := existing(t)
	output, err := FromKey(plain, nil, params(), "der")
	if err != nil {
		t.Fatal(err)
	}
	damaged := bytes.Clone(output.Bytes)
	damaged[len(damaged)-1] ^= 1
	for _, input := range [][]byte{nil, []byte("PRIVATE KEY secret"), make([]byte, MaxRequestBytes+1), damaged, output.Bytes[:len(output.Bytes)-1], append(bytes.Clone(output.Bytes), 0),
		append(bytes.Clone(output.CSR), output.CSR...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: output.Bytes}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Headers: map[string]string{"Unexpected": "secret"}, Bytes: output.Bytes}),
		append([]byte("garbage\n"), output.CSR...), append(bytes.Clone(output.CSR), []byte("trailing")...),
	} {
		if _, err := Inspect(input); err != ErrInvalid {
			t.Fatal("unsafe request accepted")
		}
		if converted, err := Convert(input, output.Summary.RequestFingerprint, "pem"); err != ErrInvalid || len(converted.Bytes) != 0 || converted.Filename != "" {
			t.Fatal("unsafe request produced output")
		}
	}
	for _, modifier := range []func(*x509.CertificateRequest){
		func(request *x509.CertificateRequest) { request.SignatureAlgorithm = x509.ECDSAWithSHA1 },
		func(request *x509.CertificateRequest) {
			request.DNSNames = []string{"demo.rootwell.invalid", "DEMO.ROOTWELL.INVALID"}
		},
		func(request *x509.CertificateRequest) { request.DNSNames = []string{" demo.rootwell.invalid "} },
		func(request *x509.CertificateRequest) {
			request.EmailAddresses = []string{"synthetic@rootwell.invalid"}
		},
		func(request *x509.CertificateRequest) {
			request.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0}}}
		},
		func(request *x509.CertificateRequest) {
			//lint:ignore SA1019 Synthetic legacy-attribute refusal regression, never production generation.
			request.Attributes = []pkix.AttributeTypeAndValueSET{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, Value: [][]pkix.AttributeTypeAndValue{{{Type: asn1.ObjectIdentifier{1, 2, 3}, Value: "synthetic-challenge-secret"}}}}}
		},
	} {
		request, err := template(params())
		if err != nil {
			t.Fatal(err)
		}
		modifier(request)
		der, err := x509.CreateCertificateRequest(rand.Reader, request, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Inspect(der); err != ErrInvalid {
			t.Fatal("weak, duplicate, ignored or unsupported request accepted")
		}
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer keymatch.ClearParsedKey(weak)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"weak.rootwell.invalid"}}, weak)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(der); err != ErrInvalid {
		t.Fatal("weak public key accepted")
	}
	weakBytes, err := x509.MarshalPKCS8PrivateKey(weak)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(weakBytes)
	if output, err := FromKey(weakBytes, nil, params(), "pem"); err != ErrInvalid || len(output.Bytes) != 0 {
		t.Fatal("weak existing key could sign a usable request")
	}
	if err := certverify.CheckRequestPolicy(nil); err == nil {
		t.Fatal("nil request accepted")
	}
	if err := certverify.CheckPublicKeyPolicy(nil); err == nil {
		t.Fatal("nil signing public key accepted")
	}
}

func TestCSRNameSubjectPasswordAndFormatRefusal(t *testing.T) {
	_, plain := existing(t)
	for _, bad := range []Params{
		{}, {DNSNames: []string{"https://demo.rootwell.invalid"}}, {DNSNames: []string{"demo.rootwell.invalid:443"}},
		{DNSNames: []string{"bad_underscore.invalid"}}, {DNSNames: []string{"*.*.rootwell.invalid"}},
		{DNSNames: []string{"a..invalid"}}, {DNSNames: []string{"-bad.invalid"}}, {DNSNames: []string{strings.Repeat("a", 64) + ".invalid"}},
		{DNSNames: []string{"192.0.2.10"}}, {DNSNames: []string{"şirkət.invalid"}},
		{DNSNames: []string{"demo.rootwell.invalid", "DEMO.ROOTWELL.INVALID"}},
		{DNSNames: make([]string, 33)}, {IPAddresses: make([]string, 9)},
		{IPAddresses: []string{"192.0.2.1/24"}}, {IPAddresses: []string{"fe80::1%eth0"}},
		{IPAddresses: []string{"192.0.2.1", "::ffff:192.0.2.1"}},
		{DNSNames: []string{"demo.rootwell.invalid"}, CommonName: "other.invalid"},
		{DNSNames: []string{"demo.rootwell.invalid"}, Country: "USA"},
		{DNSNames: []string{"demo.rootwell.invalid"}, Organization: "line\nbreak"},
		{DNSNames: []string{"demo.rootwell.invalid"}, Organization: "spoof\u202Ename"},
	} {
		if output, err := FromKey(plain, nil, bad, "pem"); err != ErrNames || len(output.Bytes) != 0 {
			t.Fatal("unsafe names/subject accepted")
		}
	}
	for _, password := range [][]byte{nil, []byte("short"), []byte("a long password with spaces"), bytes.Repeat([]byte("a"), 129)} {
		if output, err := Generate("ec-p256", params(), password); err != ErrPassword || len(output.Bytes) != 0 {
			t.Fatal("unsafe key password accepted")
		}
	}
	if output, err := Generate("unknown", params(), []byte(syntheticPassword)); err != ErrInvalid || len(output.Bytes) != 0 {
		t.Fatal("unsupported generation allowed")
	}
	if output, err := FromKey(plain, nil, params(), "pfx"); err != ErrInvalid || len(output.Bytes) != 0 {
		t.Fatal("unsupported CSR target allowed")
	}
	positive := Params{DNSNames: []string{"  DEMO.ROOTWELL.INVALID  ", "*.demo.rootwell.invalid"}, IPAddresses: []string{"::ffff:192.0.2.11"}, Organization: "Şirkət", Country: "az"}
	output, err := FromKey(plain, nil, positive, "pem")
	if err != nil || output.Summary.DNSNames[0] != "demo.rootwell.invalid" || output.Summary.IPAddresses[0] != "192.0.2.11" {
		t.Fatal("supported normalized request refused")
	}
}

func FuzzInspectCSR(f *testing.F) {
	_, plain := existing(f)
	output, err := FromKey(plain, nil, params(), "pem")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(output.Bytes)
	f.Add([]byte("PRIVATE KEY synthetic"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		summary, err := Inspect(input)
		if err != nil {
			if err != ErrInvalid {
				t.Fatal("request error echoes input")
			}
			return
		}
		if !summary.SignatureChecked || len(summary.RequestFingerprint) != 95 || len(summary.PublicFingerprint) != 95 || len(summary.DNSNames) > 32 || len(summary.IPAddresses) > 8 {
			t.Fatal("invalid successful request summary")
		}
		converted, err := Convert(input, summary.RequestFingerprint, "der")
		if err != nil || len(converted.Bytes) == 0 {
			t.Fatal("successful request cannot round trip")
		}
		again, err := Inspect(converted.Bytes)
		if err != nil || again.RequestFingerprint != summary.RequestFingerprint {
			t.Fatal("CSR round trip changed identity")
		}
	})
}
