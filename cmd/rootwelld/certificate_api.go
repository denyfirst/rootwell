package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"net/http"
	"runtime"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/browserprivateconvert"
	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

type certificateInput struct {
	Certificate    []byte
	PrivateKey     []byte
	KeyPassword    []byte
	Owner          string
	Location       string
	Fingerprint    string
	Expected       uint64
	Password       string
	OutputPassword []byte
	Pair           bool
	KeyOnly        bool
	Bundle         bool
	Primary        string
	AllowMismatch  bool
}

func (g *gate) certificateEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !signedIn {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if s.setup {
		http.Error(w, "change the setup password first", http.StatusForbidden)
		return
	}
	if !g.sameOrigin(r) {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	if runtime.GOOS != "linux" {
		http.Error(w, "certificate custody requires the Linux daemon; this host is a preview", http.StatusNotImplemented)
		return
	}
	if !s.inventoryReady {
		http.Error(w, "installation identity is not enrolled", http.StatusConflict)
		return
	}
	input, ok := readCertificateInput(w, r)
	defer func() {
		clear(input.Certificate)
		clear(input.PrivateKey)
		clear(input.KeyPassword)
		clear(input.OutputPassword)
		input.Password = ""
	}()
	if !ok {
		return
	}
	if !g.startDerivation() {
		http.Error(w, "another key or password check is running; retry shortly", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-g.derive }()
	if r.URL.Path == "/api/certificates/download" {
		g.downloadCertificate(w, r, s, input)
		return
	}
	records, generation, err := instanceaccess.ReadInventory(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
	if err != nil {
		inventoryError(w, err)
		return
	}
	if input.Expected != generation {
		inventoryError(w, inventorystore.ErrStaleGeneration)
		return
	}
	primary := input.Primary
	if r.URL.Path == "/api/certificates/save" {
		primary = input.Fingerprint
	}
	record, canonical, err := certificatepair.PrepareBundle(input.Certificate, input.PrivateKey, input.KeyPassword, input.Owner, input.Location, primary)
	defer clear(canonical)
	if err != nil {
		var choice *certificatepair.SelectionRequired
		if r.URL.Path == "/api/certificates/check" && errors.As(err, &choice) {
			if _, current := g.currentSession(r); !current || r.Context().Err() != nil {
				http.Error(w, "session no longer available", http.StatusUnauthorized)
				return
			}
			w.Header().Set("X-Rootwell-Selection", "required")
			g.writeInventoryJSON(w, http.StatusOK, choice.Candidates, generation)
			return
		}
		if errors.Is(err, browserprivateconvert.ErrInputPasswordRequired) {
			http.Error(w, "Enter the selected private key's current password, then check again.", http.StatusUnprocessableEntity)
			return
		}
		http.Error(w, "Select one certificate or a related public bundle and a supported optional key. Check the key password; CA private keys cannot be saved.", http.StatusBadRequest)
		return
	}
	for _, existing := range records {
		if existing.Fingerprint == record.Fingerprint {
			w.Header().Set("X-Rootwell-Refusal", "duplicate-certificate")
			inventoryError(w, publicinventory.ErrDuplicate)
			return
		}
	}
	if _, current := g.currentSession(r); !current || r.Context().Err() != nil {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	if r.URL.Path == "/api/certificates/check" {
		g.writeInventoryJSON(w, http.StatusOK, []publicinventory.Record{record}, generation)
		return
	}
	if input.Fingerprint != record.Fingerprint {
		http.Error(w, "selection changed; check the files again", http.StatusConflict)
		return
	}
	// Prepare is repeated by the store itself; a preview never grants write authority.
	record, generation, err = instanceaccess.AppendCertificateMaterial(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Expected,
		input.Certificate, input.PrivateKey, input.KeyPassword, input.Owner, input.Location, input.Fingerprint, input.AllowMismatch)
	if err != nil {
		inventoryError(w, err)
		return
	}
	g.writeInventoryJSON(w, http.StatusCreated, []publicinventory.Record{record}, generation)
}

// Parse one bounded JSON object, reject duplicate/unknown/wrong-mode fields
// and keep byte secrets out of reflected errors and strings where possible.
func readCertificateInput(w http.ResponseWriter, r *http.Request) (certificateInput, bool) {
	var input certificateInput
	bad := func() (certificateInput, bool) {
		clear(input.Certificate)
		clear(input.PrivateKey)
		clear(input.KeyPassword)
		clear(input.OutputPassword)
		http.Error(w, "invalid certificate request", http.StatusBadRequest)
		return certificateInput{}, false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return input, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1200<<10))
	defer clear(body)
	if err != nil || len(body) == 0 || !utf8.Valid(body) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(body))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return bad()
	}
	seen := map[string]bool{}
	readString := func(target *string) error {
		var value *string
		if err := d.Decode(&value); err != nil || value == nil {
			return certificatepair.ErrInvalid
		}
		*target = *value
		return nil
	}
	readBytes := func(target *[]byte) error {
		var value string
		if err := readString(&value); err != nil {
			return err
		}
		var err error
		*target, err = base64.StdEncoding.Strict().DecodeString(value)
		return err
	}
	download := r.URL.Path == "/api/certificates/download"
	for d.More() {
		token, err := d.Token()
		name, yes := token.(string)
		if err != nil || !yes || seen[name] {
			return bad()
		}
		seen[name] = true
		switch name {
		case "certificate":
			if download {
				return bad()
			}
			err = readBytes(&input.Certificate)
		case "private_key":
			if download {
				return bad()
			}
			err = readBytes(&input.PrivateKey)
		case "key_password":
			if download {
				return bad()
			}
			err = readBytes(&input.KeyPassword)
		case "owner":
			if download {
				return bad()
			}
			err = readString(&input.Owner)
		case "location":
			if download {
				return bad()
			}
			err = readString(&input.Location)
		case "fingerprint":
			err = readString(&input.Fingerprint)
		case "primary_fingerprint":
			if download || r.URL.Path != "/api/certificates/check" {
				return bad()
			}
			err = readString(&input.Primary)
		case "allow_mismatch":
			if download || r.URL.Path != "/api/certificates/save" {
				return bad()
			}
			var value *bool
			err = d.Decode(&value)
			if value == nil {
				return bad()
			}
			input.AllowMismatch = *value
		case "key_only", "bundle":
			if !download {
				return bad()
			}
			var value *bool
			err = d.Decode(&value)
			if value == nil {
				return bad()
			}
			if name == "key_only" {
				input.KeyOnly = *value
			} else {
				input.Bundle = *value
			}
		case "expected_generation":
			err = d.Decode(&input.Expected)
		case "password":
			if !download {
				return bad()
			}
			err = readString(&input.Password)
		case "output_password":
			if !download {
				return bad()
			}
			err = readBytes(&input.OutputPassword)
		case "pair":
			if !download {
				return bad()
			}
			var value *bool
			err = d.Decode(&value)
			if value == nil {
				err = certificatepair.ErrInvalid
			} else {
				input.Pair = *value
			}
		default:
			return bad()
		}
		if err != nil {
			return bad()
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') {
		return bad()
	}
	if _, err := d.Token(); err != io.EOF || !seen["expected_generation"] || input.Expected == 0 || len(input.Certificate) > certificatepair.MaxBundleBytes || len(input.PrivateKey) > 64<<10 || len(input.KeyPassword) > 256 || len(input.OutputPassword) > 256 || len(input.Password) > 256 || !publicinventory.ValidOwner(input.Owner) || (input.Location != "" && publicinventory.ValidateLocation(input.Location) != nil) || (seen["primary_fingerprint"] && !publicinventory.ValidFingerprint(input.Primary)) {
		return bad()
	}
	if download {
		secret := input.Pair || input.KeyOnly
		if !publicinventory.ValidFingerprint(input.Fingerprint) || !seen["pair"] || (input.Pair && input.KeyOnly) || (input.Bundle && secret) || (!secret && (seen["password"] || seen["output_password"])) || (secret && (input.Password == "" || len(input.OutputPassword) == 0)) {
			return bad()
		}
	} else if len(input.Certificate) == 0 || (r.URL.Path == "/api/certificates/save" && !publicinventory.ValidFingerprint(input.Fingerprint)) || (r.URL.Path == "/api/certificates/check" && seen["fingerprint"]) {
		return bad()
	}
	return input, true
}

func (g *gate) downloadCertificate(w http.ResponseWriter, r *http.Request, s session, input certificateInput) {
	if input.Pair || input.KeyOnly {
		if !g.allowAttempt() {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many attempts; wait one minute", http.StatusTooManyRequests)
			return
		}
		setup, err := instanceaccess.Authenticate(g.accessPath, input.Password)
		if err != nil || setup {
			if errors.Is(err, instanceaccess.ErrWrongPassword) {
				http.Error(w, "password not accepted", http.StatusUnauthorized)
			} else {
				http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		if bytes.Equal([]byte(input.Password), input.OutputPassword) {
			http.Error(w, "Use a separate password for the downloaded key.", http.StatusBadRequest)
			return
		}
	}
	var output []byte
	defer func() { clear(output) }()
	err := instanceaccess.WithCertificate(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, input.Expected, input.Fingerprint,
		func(record publicinventory.Record, key []byte) error {
			certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: record.DER})
			if !input.Pair && !input.KeyOnly {
				if input.Bundle {
					certificate = certificatepair.PublicPEM(record.BundleDER)
					if len(certificate) == 0 {
						certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: record.DER})
					}
				}
				output = certificate
				return nil
			}
			defer clear(certificate)
			if len(key) == 0 {
				return certificatepair.ErrInvalid
			}
			if input.Pair && record.KeyStatus != "matched" {
				return certificatepair.ErrInvalid
			}
			metadata, err := browserprivateconvert.Inspect(key)
			if err != nil {
				return err
			}
			encrypted, _, err := browserprivateconvert.ExportEncrypted(key, metadata.PublicFingerprint, input.OutputPassword)
			if err != nil {
				return err
			}
			defer clear(encrypted)
			if input.KeyOnly {
				output = bytes.Clone(encrypted)
				return nil
			}
			var archive bytes.Buffer
			defer func() { clear(archive.Bytes()) }()
			z := zip.NewWriter(&archive)
			for _, file := range []struct {
				name string
				body []byte
			}{{"certificate.pem", certificate}, {"private-key.encrypted.pem", encrypted}, {"included-certificates.pem", certificatepair.PublicPEM(record.BundleDER)}} {
				if file.name == "included-certificates.pem" && len(record.BundleDER) < 2 {
					continue
				}
				if len(file.body) == 0 {
					continue
				}
				writer, err := z.Create(file.name)
				if err != nil {
					return err
				}
				if _, err := writer.Write(file.body); err != nil {
					return err
				}
			}
			if err := z.Close(); err != nil {
				return err
			}
			output = bytes.Clone(archive.Bytes())
			return nil
		})
	if err != nil {
		if errors.Is(err, browserprivateconvert.ErrPassword) || errors.Is(err, certificatepair.ErrInvalid) {
			http.Error(w, "Key download refused. Pair export requires a matching key. Use a separate password of 20–128 non-space ASCII characters for key downloads.", http.StatusBadRequest)
		} else {
			inventoryError(w, err)
		}
		return
	}
	if _, current := g.currentSession(r); !current || r.Context().Err() != nil {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		http.Error(w, "download unavailable", http.StatusServiceUnavailable)
		return
	}
	ext, media := ".pem", "application/x-pem-file"
	if input.Pair {
		ext, media = ".zip", "application/zip"
	}
	w.Header().Set("Content-Type", media)
	w.Header().Set("Content-Disposition", `attachment; filename="rootwell-certificate-`+hex.EncodeToString(nonce[:])+ext+`"`)
	_, _ = w.Write(output)
}
