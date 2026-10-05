//go:build ignore

// Disposable synthetic CSR/certificate fixtures only; never real key custody.
package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/denyfirst/rootwell/internal/csrworkbench"
	"github.com/denyfirst/rootwell/internal/keymatch"
)

const password = "synthetic-CSR-output-password-2026-67de"

func main() {
	writeFiles := flag.Bool("write-files", false, "write disposable synthetic material for UI tests")
	readZip := flag.Bool("read-zip", false, "decode a disposable WASM ZIP from bounded stdin for interoperability tests")
	flag.Parse()
	if flag.NArg() != 0 || (*writeFiles && *readZip) {
		fail()
	}
	if *readZip {
		unpack()
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	defer keymatch.ClearParsedKey(key)
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	check(err)
	defer clear(plain)
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: plain})
	defer clear(private)
	params := csrworkbench.Params{DNSNames: []string{"demo.rootwell.invalid", "www.demo.rootwell.invalid"}, Organization: "Synthetic test only", Country: "AZ"}
	output, err := csrworkbench.FromKey(private, nil, params, "der")
	check(err)
	request, err := x509.ParseCertificateRequest(output.Bytes)
	check(err)
	template := &x509.Certificate{SerialNumber: big.NewInt(2026), Subject: request.Subject, DNSNames: request.DNSNames,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	check(err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	defer keymatch.ClearParsedKey(other)
	different, err := x509.CreateCertificate(rand.Reader, template, template, other.Public(), other)
	check(err)
	files := map[string][]byte{"synthetic-request.csr": output.CSR, "synthetic-request.der": output.Bytes, "synthetic-key.pem": private,
		"synthetic-certificate.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), "synthetic-other-certificate.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: different})}
	if *writeFiles {
		directory, err := os.MkdirTemp("", "rootwell-synthetic-csr-")
		check(err)
		for name, data := range files {
			check(os.WriteFile(filepath.Join(directory, name), data, 0o600))
		}
		check(json.NewEncoder(os.Stdout).Encode(map[string]string{"directory": directory, "password": password}))
		return
	}
	result := make(map[string]string)
	for name, data := range files {
		result[name] = base64.StdEncoding.EncodeToString(data)
	}
	result["password"] = password
	check(json.NewEncoder(os.Stdout).Encode(result))
}

func unpack() {
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 256<<10+1))
	check(err)
	defer clear(input)
	if len(input) == 0 || len(input) > 256<<10 {
		fail()
	}
	archive, err := zip.NewReader(bytes.NewReader(input), int64(len(input)))
	check(err)
	if len(archive.File) != 2 {
		fail()
	}
	result := make(map[string]string)
	for _, file := range archive.File {
		if file.Name != "encrypted-private-key.pem" && file.Name != "certificate-request.csr" {
			fail()
		}
		if _, exists := result[file.Name]; exists || file.UncompressedSize64 > 96<<10 {
			fail()
		}
		stream, err := file.Open()
		check(err)
		data, err := io.ReadAll(io.LimitReader(stream, 96<<10+1))
		_ = stream.Close()
		check(err)
		if len(data) > 96<<10 {
			clear(data)
			fail()
		}
		result[file.Name] = base64.StdEncoding.EncodeToString(data)
		clear(data)
	}
	check(json.NewEncoder(os.Stdout).Encode(result))
}
func check(err error) {
	if err != nil {
		fail()
	}
}
func fail() { _, _ = fmt.Fprintln(os.Stderr, "synthetic CSR fixture operation failed"); os.Exit(1) }

// Keep signer support explicit in this standalone test helper.
var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)
