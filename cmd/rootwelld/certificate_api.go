package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/browserprivateconvert"
	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/certstore"
	"github.com/denyfirst/rootwell/internal/keymatch"
	"github.com/denyfirst/rootwell/internal/pfxcreate"
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
	OutputPassword []byte
	Pair           bool
	KeyOnly        bool
	// PFX asks for the certificate, its issuers and its key in one PFX for
	// Windows and IIS; OlderWindows for one Windows Server 2016 can read.
	PFX           bool
	OlderWindows  bool
	Bundle        bool
	Primary       string
	AllowMismatch bool
	// Replaces names the saved certificate this one is to take over.
	Replaces string
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
	if !g.sameOrigin(r) {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	input, ok := readCertificateInput(w, r)
	defer func() {
		clear(input.Certificate)
		clear(input.PrivateKey)
		clear(input.KeyPassword)
		clear(input.OutputPassword)
	}()
	if !ok {
		return
	}
	if r.URL.Path == "/api/certificates/download" && (input.Pair || input.KeyOnly || input.PFX) && !s.isFresh(g.now()) {
		needFresh(w)
		return
	}
	if !g.slot(r) {
		http.Error(w, "Another key or password check is running. Try again.", http.StatusServiceUnavailable)
		return
	}
	defer g.release()
	if r.URL.Path == "/api/certificates/key/check" || r.URL.Path == "/api/certificates/key/save" {
		g.attachCertificateKey(w, r, s, input)
		return
	}
	if r.URL.Path == "/api/certificates/download" {
		g.downloadCertificate(w, r, s, input)
		return
	}
	records, generation, err := g.certificates.List()
	if err != nil {
		inventoryError(w, err)
		return
	}
	if input.Expected != generation {
		inventoryError(w, certstore.ErrStale)
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
			if !g.stillReady(r, s) || r.Context().Err() != nil {
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
		if errors.Is(err, browserprivateconvert.ErrInputPasswordWrong) {
			keyPasswordWrong(w)
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
	if !g.stillReady(r, s) || r.Context().Err() != nil {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	if r.URL.Path == "/api/certificates/check" {
		// What saving would do: finish a request kept here, and which saved
		// certificate it would take over. Saving decides again.
		plan, err := g.certificates.Successor(record)
		if err != nil {
			inventoryError(w, err)
			return
		}
		g.writeInventory(w, http.StatusOK, []publicinventory.Record{record}, generation, func(out *inventoryOutput) {
			out.Records[0].FinishesRequest, out.Records[0].Renews, out.Records[0].Replaces = plan.Finishes, plan.Renews, plan.Replaces
		})
		return
	}
	if input.Fingerprint != record.Fingerprint {
		http.Error(w, "selection changed; check the files again", http.StatusConflict)
		return
	}
	// Prepare is repeated by the store itself; a preview never grants write authority.
	record, generation, err = g.certificates.Save(input.Expected, input.Certificate, input.PrivateKey, input.KeyPassword, input.Owner, input.Location, input.Fingerprint, input.AllowMismatch, input.Replaces)
	if err != nil {
		inventoryError(w, err)
		return
	}
	g.publishCertificateSave(w, r, s, record, generation)
}

// keyPasswordWrong answers a key password that does not open the key. The
// header lets the page tell it from a key that still needs its password.
func keyPasswordWrong(w http.ResponseWriter) {
	w.Header().Set("X-Rootwell-Refusal", "key-password-wrong")
	http.Error(w, "That password does not open the key.", http.StatusUnprocessableEntity)
}

func (g *gate) publishCertificateSave(w http.ResponseWriter, r *http.Request, s session, record publicinventory.Record, generation uint64) {
	if !g.stillReady(r, s) || r.Context().Err() != nil {
		// The commit may already be durable. Never turn publication loss into a
		// definite pre-write refusal that would encourage a blind duplicate Save.
		http.Error(w, "Save outcome uncertain; sign in and refresh before retrying.", http.StatusServiceUnavailable)
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
	attach := r.URL.Path == "/api/certificates/key/check" || r.URL.Path == "/api/certificates/key/save"
	attachSave := r.URL.Path == "/api/certificates/key/save"
	for d.More() {
		token, err := d.Token()
		name, yes := token.(string)
		if err != nil || !yes || seen[name] {
			return bad()
		}
		seen[name] = true
		switch name {
		case "certificate":
			if download || attach {
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
			if download || attach {
				return bad()
			}
			err = readString(&input.Owner)
		case "location":
			if download || attach {
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
		case "replaces":
			if r.URL.Path != "/api/certificates/save" {
				return bad()
			}
			err = readString(&input.Replaces)
			if err == nil && !publicinventory.ValidFingerprint(input.Replaces) {
				return bad()
			}
		case "allow_mismatch":
			if download || (r.URL.Path != "/api/certificates/save" && !attachSave) {
				return bad()
			}
			var value *bool
			err = d.Decode(&value)
			if value == nil {
				return bad()
			}
			input.AllowMismatch = *value
		case "key_only", "bundle", "pfx", "older_windows":
			if !download {
				return bad()
			}
			var value *bool
			err = d.Decode(&value)
			if value == nil {
				return bad()
			}
			switch name {
			case "key_only":
				input.KeyOnly = *value
			case "bundle":
				input.Bundle = *value
			case "pfx":
				input.PFX = *value
			default:
				input.OlderWindows = *value
			}
		case "expected_generation":
			err = d.Decode(&input.Expected)
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
	if _, err := d.Token(); err != io.EOF || !seen["expected_generation"] || input.Expected == 0 || len(input.Certificate) > certificatepair.MaxBundleBytes || len(input.PrivateKey) > 64<<10 || len(input.KeyPassword) > 256 || len(input.OutputPassword) > 256 || !publicinventory.ValidOwner(input.Owner) || (input.Location != "" && publicinventory.ValidateLocation(input.Location) != nil) || (seen["primary_fingerprint"] && !publicinventory.ValidFingerprint(input.Primary)) {
		return bad()
	}
	if attach {
		if !publicinventory.ValidFingerprint(input.Fingerprint) || len(input.PrivateKey) == 0 {
			return bad()
		}
	} else if download {
		secret := input.Pair || input.KeyOnly || input.PFX
		kinds := 0
		for _, chosen := range []bool{input.Pair, input.KeyOnly, input.PFX, input.Bundle} {
			if chosen {
				kinds++
			}
		}
		if !publicinventory.ValidFingerprint(input.Fingerprint) || !seen["pair"] || kinds > 1 || (input.OlderWindows && !input.PFX) || (!secret && seen["output_password"]) || (secret && len(input.OutputPassword) == 0) {
			return bad()
		}
	} else if len(input.Certificate) == 0 || (r.URL.Path == "/api/certificates/save" && !publicinventory.ValidFingerprint(input.Fingerprint)) || (r.URL.Path == "/api/certificates/check" && seen["fingerprint"]) {
		return bad()
	}
	return input, true
}

func (g *gate) attachCertificateKey(w http.ResponseWriter, r *http.Request, s session, input certificateInput) {
	save := r.URL.Path == "/api/certificates/key/save"
	if !g.stillReady(r, s) || r.Context().Err() != nil {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	var record publicinventory.Record
	var err error
	generation := input.Expected
	if save {
		record, generation, err = g.certificates.AttachKey(input.Expected, input.Fingerprint, input.PrivateKey, input.KeyPassword, input.AllowMismatch)
	} else {
		record, err = g.certificates.CheckKey(input.Expected, input.Fingerprint, input.PrivateKey, input.KeyPassword)
	}
	if err != nil {
		switch {
		case errors.Is(err, certstore.ErrKeyExists):
			w.Header().Set("X-Rootwell-Refusal", "key-already-attached")
			http.Error(w, "a key is already attached; no key was replaced", http.StatusConflict)
		case errors.Is(err, browserprivateconvert.ErrInputPasswordRequired):
			http.Error(w, "enter the selected key's current password", http.StatusUnprocessableEntity)
		case errors.Is(err, browserprivateconvert.ErrInputPasswordWrong):
			keyPasswordWrong(w)
		case errors.Is(err, certificatepair.ErrInvalid):
			http.Error(w, "key or acknowledgement not accepted; no key was attached", http.StatusBadRequest)
		default:
			inventoryError(w, err)
		}
		return
	}
	if !g.stillReady(r, s) || r.Context().Err() != nil {
		if save {
			// The atomic write completed, but this session cannot receive confirmation.
			// Do not classify it as a definitive pre-write authentication refusal.
			http.Error(w, "save outcome uncertain; sign in and refresh before retrying", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "session no longer available", http.StatusUnauthorized)
		}
		return
	}
	g.writeInventoryJSON(w, http.StatusOK, []publicinventory.Record{record}, generation)
}

func (g *gate) downloadCertificate(w http.ResponseWriter, r *http.Request, s session, input certificateInput) {
	var output []byte
	defer func() { clear(output) }()
	err := g.certificates.WithCertificate(input.Expected, input.Fingerprint,
		func(record publicinventory.Record, key []byte) error {
			certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: record.DER})
			if !input.Pair && !input.KeyOnly && !input.PFX {
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
			if (input.Pair || input.PFX) && record.KeyStatus != "matched" {
				return certificatepair.ErrInvalid
			}
			if input.PFX {
				// Windows and IIS take one PFX: the certificate, its issuers
				// and its key, locked with the download password.
				profile := pfxcreate.Modern
				if input.OlderWindows {
					profile = pfxcreate.OlderWindows
				}
				chain := certificatepair.PublicPEM(intermediates(record.IssuerDER))
				defer clear(chain)
				return keymatch.WithPrivateKey(key, func(parsed any, _ keymatch.Encoding) error {
					made, err := pfxcreate.CreateWithParsedKeyProfile(certificate, parsed, chain, string(input.OutputPassword), profile)
					if err != nil {
						return certificatepair.ErrInvalid
					}
					output = made
					return nil
				})
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
			// The names nginx, Apache and certbot use. The key stays locked
			// with the download password; there is no plaintext key export.
			chain := certificatepair.PublicPEM(record.IssuerDER)
			var archive bytes.Buffer
			defer func() { clear(archive.Bytes()) }()
			z := zip.NewWriter(&archive)
			for _, file := range []struct {
				name string
				body []byte
			}{{"fullchain.pem", append(bytes.Clone(certificate), chain...)}, {"cert.pem", certificate}, {"chain.pem", chain}, {"privkey.pem", encrypted}, {"HOW-TO-INSTALL.txt", []byte(installNotes)}} {
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
	if !g.stillReady(r, s) || r.Context().Err() != nil {
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
	if input.PFX {
		ext, media = ".pfx", "application/x-pkcs12"
	}
	w.Header().Set("Content-Type", media)
	w.Header().Set("Content-Disposition", `attachment; filename="rootwell-certificate-`+hex.EncodeToString(nonce[:])+ext+`"`)
	_, _ = w.Write(output)
}

// installNotes go in the ZIP for nginx and Apache. The key in it stays locked
// with the download password; a server reads it with that password, or after
// it is opened on the server itself (C111: Rootwell sends no open key).
const installNotes = `These files are for nginx, Apache, HAProxy and other servers that read PEM.

  fullchain.pem  the certificate, then its issuers
  cert.pem       the certificate alone
  chain.pem      the issuers alone
  privkey.pem    the private key, locked with the password you chose

nginx
  ssl_certificate      /etc/nginx/ssl/fullchain.pem;
  ssl_certificate_key  /etc/nginx/ssl/privkey.pem;
  ssl_password_file    /etc/nginx/ssl/privkey.pass;
  Put the download password, alone on one line, in privkey.pass.
  Make privkey.pem and privkey.pass readable by root only (chmod 600).

Apache
  Apache asks for the password at every start, so open the key once on the
  server, then keep it readable by root only:
    openssl pkey -in privkey.pem -out privkey-open.pem
    chmod 600 privkey-open.pem
  SSLCertificateFile     /etc/ssl/rootwell/fullchain.pem
  SSLCertificateKeyFile  /etc/ssl/rootwell/privkey-open.pem

After installing, reload the server and check the site with Website check.
`

// intermediates leaves out the self-signed roots: a PFX carries the issuers
// between the certificate and its root, and Windows trusts the root itself.
func intermediates(issuers [][]byte) [][]byte {
	var out [][]byte
	for _, der := range issuers {
		c, err := x509.ParseCertificate(der)
		if err != nil || (bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil) {
			continue
		}
		out = append(out, der)
	}
	return out
}
