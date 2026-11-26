package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/certstore"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

type inventoryLocationInput struct {
	Fingerprint        string
	Location           string
	ExpectedGeneration uint64
}

type inventoryOwnerInput struct {
	Fingerprint        string
	Owner              string
	ExpectedGeneration uint64
}

type inventoryLocationChangeInput struct {
	Fingerprint        string
	OldLocation        string
	NewLocation        string
	Action             certstore.LocationChange
	ExpectedGeneration uint64
}

type inventoryDeleteInput struct {
	Fingerprint        string
	TypedFingerprint   string
	Confirmation       string
	ExpectedGeneration uint64
}

type inventoryDeleteOutput struct {
	Fingerprint string `json:"fingerprint"`
	Generation  uint64 `json:"generation"`
	Deleted     bool   `json:"deleted"`
}

type inventoryItem struct {
	HasPrivateKey    bool                   `json:"has_private_key"`
	KeyStatus        string                 `json:"key_status"`
	BundleCount      int                    `json:"bundle_count"`
	Fingerprint      string                 `json:"fingerprint"`
	Subject          string                 `json:"subject"`
	Issuer           string                 `json:"issuer"`
	DNSNames         []string               `json:"dns_names"`
	IPAddresses      []string               `json:"ip_addresses"`
	KeyType          string                 `json:"key_type"`
	Chain            []chainLink            `json:"chain"`
	NotBefore        string                 `json:"not_before"`
	NotAfter         string                 `json:"not_after"`
	Owner            string                 `json:"owner"`
	Location         string                 `json:"location"`
	Locations        []string               `json:"locations"`
	ImportGeneration uint64                 `json:"import_generation"`
	ImportedAt       string                 `json:"imported_at,omitempty"`
	Expiry           publicinventory.Expiry `json:"expiry"`
}

func (g *gate) inventoryLocationEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
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
	input, ok := readInventoryLocationInput(w, r)
	if !ok {
		return
	}
	updated, generation, err := g.certificates.AddLocation(input.ExpectedGeneration, input.Fingerprint, input.Location)
	if err != nil {
		inventoryError(w, err)
		return
	}
	g.writeInventoryJSON(w, http.StatusOK, []publicinventory.Record{updated}, generation)
}

func readInventoryLocationInput(w http.ResponseWriter, r *http.Request) (inventoryLocationInput, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return inventoryLocationInput{}, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || len(body) == 0 || !utf8.Valid(body) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationInput{}, false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationInput{}, false
	}
	var input inventoryLocationInput
	seen := make(map[string]bool, 3)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationInput{}, false
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationInput{}, false
		}
		seen[name] = true
		switch name {
		case "fingerprint":
			err = d.Decode(&input.Fingerprint)
		case "location":
			err = d.Decode(&input.Location)
		case "expected_generation":
			err = d.Decode(&input.ExpectedGeneration)
		default:
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationInput{}, false
		}
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationInput{}, false
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationInput{}, false
	}
	if _, err := d.Token(); err != io.EOF || !seen["fingerprint"] || !seen["location"] || !seen["expected_generation"] ||
		len(input.Fingerprint) == 0 || len(input.Fingerprint) > 128 || input.Location == "" || input.ExpectedGeneration == 0 {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationInput{}, false
	}
	if publicinventory.ValidateLocation(input.Location) != nil {
		http.Error(w, "invalid location", http.StatusBadRequest)
		return inventoryLocationInput{}, false
	}
	return input, true
}

func (g *gate) inventoryLocationChangeEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
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
	input, ok := readInventoryLocationChangeInput(w, r)
	if !ok {
		return
	}
	updated, generation, err := g.certificates.ChangeLocation(input.ExpectedGeneration, input.Fingerprint, input.OldLocation, input.NewLocation, input.Action)
	if err != nil {
		inventoryError(w, err)
		return
	}
	g.writeInventoryJSON(w, http.StatusOK, []publicinventory.Record{updated}, generation)
}

func readInventoryLocationChangeInput(w http.ResponseWriter, r *http.Request) (inventoryLocationChangeInput, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return inventoryLocationChangeInput{}, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || len(body) == 0 || !utf8.Valid(body) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationChangeInput{}, false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationChangeInput{}, false
	}
	var input inventoryLocationChangeInput
	var action string
	seen := make(map[string]bool, 5)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationChangeInput{}, false
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationChangeInput{}, false
		}
		seen[name] = true
		switch name {
		case "fingerprint":
			err = d.Decode(&input.Fingerprint)
		case "old_location":
			err = d.Decode(&input.OldLocation)
		case "new_location":
			err = d.Decode(&input.NewLocation)
		case "action":
			err = d.Decode(&action)
		case "expected_generation":
			err = d.Decode(&input.ExpectedGeneration)
		default:
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationChangeInput{}, false
		}
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationChangeInput{}, false
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationChangeInput{}, false
	}
	if _, err := d.Token(); err != io.EOF || !seen["fingerprint"] || !seen["old_location"] || !seen["action"] || !seen["expected_generation"] ||
		len(input.Fingerprint) == 0 || len(input.Fingerprint) > 128 || input.ExpectedGeneration == 0 ||
		publicinventory.ValidateLocation(input.OldLocation) != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationChangeInput{}, false
	}
	switch action {
	case "rename":
		if !seen["new_location"] || publicinventory.ValidateLocation(input.NewLocation) != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationChangeInput{}, false
		}
		input.Action = certstore.Rename
	case "remove":
		if seen["new_location"] {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryLocationChangeInput{}, false
		}
		input.Action = certstore.Remove
	default:
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryLocationChangeInput{}, false
	}
	return input, true
}

func (g *gate) inventoryOwnerEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
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
	input, ok := readInventoryOwnerInput(w, r)
	if !ok {
		return
	}
	updated, generation, err := g.certificates.SetOwner(input.ExpectedGeneration, input.Fingerprint, input.Owner)
	if err != nil {
		inventoryError(w, err)
		return
	}
	g.writeInventoryJSON(w, http.StatusOK, []publicinventory.Record{updated}, generation)
}

func readInventoryOwnerInput(w http.ResponseWriter, r *http.Request) (inventoryOwnerInput, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return inventoryOwnerInput{}, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || len(body) == 0 || !utf8.Valid(body) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryOwnerInput{}, false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryOwnerInput{}, false
	}
	var input inventoryOwnerInput
	seen := make(map[string]bool, 3)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryOwnerInput{}, false
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryOwnerInput{}, false
		}
		seen[name] = true
		switch name {
		case "fingerprint":
			err = d.Decode(&input.Fingerprint)
		case "owner":
			var raw json.RawMessage
			err = d.Decode(&raw)
			if err == nil {
				if len(raw) == 0 || raw[0] != '"' {
					http.Error(w, "invalid request body", http.StatusBadRequest)
					return inventoryOwnerInput{}, false
				}
				err = json.Unmarshal(raw, &input.Owner)
			}
		case "expected_generation":
			err = d.Decode(&input.ExpectedGeneration)
		default:
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryOwnerInput{}, false
		}
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryOwnerInput{}, false
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryOwnerInput{}, false
	}
	if _, err := d.Token(); err != io.EOF || !seen["fingerprint"] || !seen["owner"] || !seen["expected_generation"] ||
		len(input.Fingerprint) == 0 || len(input.Fingerprint) > 128 || input.ExpectedGeneration == 0 || !publicinventory.ValidOwner(input.Owner) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryOwnerInput{}, false
	}
	return input, true
}

func (g *gate) inventoryDeleteEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
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
	input, ok := readInventoryDeleteInput(w, r)
	if !ok {
		return
	}
	generation, err := g.certificates.Delete(input.ExpectedGeneration, input.Fingerprint, s.isFresh(g.now()))
	if err != nil {
		inventoryError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(inventoryDeleteOutput{Fingerprint: input.Fingerprint, Generation: generation, Deleted: true})
}

func readInventoryDeleteInput(w http.ResponseWriter, r *http.Request) (inventoryDeleteInput, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return inventoryDeleteInput{}, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || len(body) == 0 || !utf8.Valid(body) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryDeleteInput{}, false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryDeleteInput{}, false
	}
	var input inventoryDeleteInput
	seen := make(map[string]bool, 4)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryDeleteInput{}, false
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryDeleteInput{}, false
		}
		seen[name] = true
		switch name {
		case "fingerprint":
			err = d.Decode(&input.Fingerprint)
		case "typed_fingerprint":
			err = d.Decode(&input.TypedFingerprint)
		case "confirmation":
			err = d.Decode(&input.Confirmation)
		case "expected_generation":
			err = d.Decode(&input.ExpectedGeneration)
		default:
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryDeleteInput{}, false
		}
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return inventoryDeleteInput{}, false
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryDeleteInput{}, false
	}
	if _, err := d.Token(); err != io.EOF || !seen["fingerprint"] || !seen["typed_fingerprint"] ||
		!seen["confirmation"] || !seen["expected_generation"] || len(input.Fingerprint) == 0 || len(input.Fingerprint) > 128 ||
		input.TypedFingerprint != input.Fingerprint || input.Confirmation != "delete-public-record" || input.ExpectedGeneration == 0 {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return inventoryDeleteInput{}, false
	}
	return input, true
}

type inventoryOutput struct {
	Generation uint64          `json:"generation"`
	Records    []inventoryItem `json:"records"`
}

// inventoryEndpoint lists the saved certificates. Certificates are added on
// /api/certificates/save, never here.
func (g *gate) inventoryEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if !signedIn {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("X-Rootwell-Request") != "1" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "request origin refused", http.StatusForbidden)
		return
	}
	records, generation, err := g.certificates.List()
	if err != nil {
		inventoryError(w, err)
		return
	}
	g.writeInventoryJSON(w, http.StatusOK, records, generation)
}

func inventoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, publicinventory.ErrDuplicate):
		http.Error(w, "certificate is already saved", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrLocationDuplicate):
		http.Error(w, "location is already listed for this certificate", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrLocationCapacity):
		http.Error(w, "certificate location limit reached", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrLocationMissing):
		http.Error(w, "location is no longer listed; refresh first", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrLocationUnchanged):
		http.Error(w, "location is unchanged", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrOwnerUnchanged):
		http.Error(w, "owner is unchanged", http.StatusConflict)
	case errors.Is(err, certstore.ErrKeyNeedsCode):
		needFresh(w)
	case errors.Is(err, certstore.ErrNotFound):
		http.Error(w, "certificate is no longer in the inventory; refresh first", http.StatusNotFound)
	case errors.Is(err, certstore.ErrStale):
		http.Error(w, "inventory changed; refresh before changing metadata", http.StatusConflict)
	case errors.Is(err, certstore.ErrFull):
		http.Error(w, "inventory capacity reached", http.StatusConflict)
	case errors.Is(err, publicinventory.ErrLabel), errors.Is(err, publicinventory.ErrCertSize):
		http.Error(w, "invalid owner/location or certificate size", http.StatusBadRequest)
	case errors.Is(err, certstore.ErrUnavailable):
		http.Error(w, "the certificate vault could not be read; inspect storage before retrying", http.StatusServiceUnavailable)
	default:
		http.Error(w, "public certificate inventory operation refused", http.StatusBadRequest)
	}
}

// chainLink is one issuer above a saved certificate, nearest first.
type chainLink struct {
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"not_after"`
	Root     bool   `json:"root"`
}

// certificateFacts reads what a page shows beside a saved certificate from
// its own public certificates: its IP names, its key type and its issuers.
func certificateFacts(r publicinventory.Record) (ips []string, keyType string, chain []chainLink) {
	ips, chain = []string{}, []chainLink{}
	c, err := x509.ParseCertificate(r.DER)
	if err != nil {
		return ips, "", chain
	}
	for _, ip := range c.IPAddresses {
		ips = append(ips, ip.String())
	}
	switch key := c.PublicKey.(type) {
	case *rsa.PublicKey:
		keyType = fmt.Sprintf("RSA %d", key.N.BitLen())
	case *ecdsa.PublicKey:
		keyType = "ECDSA " + key.Curve.Params().Name
	case ed25519.PublicKey:
		keyType = "Ed25519"
	}
	for _, der := range r.IssuerDER {
		issuer, err := x509.ParseCertificate(der)
		if err != nil {
			break
		}
		chain = append(chain, chainLink{Subject: issuer.Subject.String(), Issuer: issuer.Issuer.String(),
			NotAfter: issuer.NotAfter.UTC().Format(time.RFC3339), Root: bytes.Equal(issuer.RawIssuer, issuer.RawSubject) && issuer.CheckSignatureFrom(issuer) == nil})
	}
	return ips, keyType, chain
}

func (g *gate) writeInventoryJSON(w http.ResponseWriter, status int, records []publicinventory.Record, generation uint64) {
	now := g.now().UTC().Truncate(time.Second)
	if now.Year() < 0 || now.Year() > 9999 {
		http.Error(w, "server clock unavailable; expiry was not calculated", http.StatusServiceUnavailable)
		return
	}
	items := make([]inventoryItem, 0, len(records))
	for _, r := range records {
		ips, keyType, chain := certificateFacts(r)
		items = append(items, inventoryItem{Fingerprint: r.Fingerprint, Subject: r.Subject, Issuer: r.Issuer, DNSNames: append([]string{}, r.DNSNames...),
			IPAddresses: ips, KeyType: keyType, Chain: chain,
			NotBefore: r.NotBefore, NotAfter: r.NotAfter, Owner: r.Owner, Location: r.Location, Locations: append([]string{}, r.Locations...),
			ImportGeneration: r.ImportGeneration, ImportedAt: r.ImportedAt, HasPrivateKey: r.HasPrivateKey, KeyStatus: r.KeyStatus, BundleCount: len(r.BundleDER), Expiry: publicinventory.ObserveExpiry(r, now)})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(inventoryOutput{Generation: generation, Records: items})
}
