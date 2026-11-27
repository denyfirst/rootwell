package main

import (
	"crypto/x509"
	"net/http"
	"slices"

	"github.com/denyfirst/rootwell/internal/certstore"
	"github.com/denyfirst/rootwell/internal/csrworkbench"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

// requestInput makes a request whose key stays in Rootwell. Either Renews
// names a saved certificate, whose names and organization the request takes,
// or DNSNames and IPAddresses list what the certificate is for, with optional organization
// details. The key is made here and never sent.
type requestInput struct {
	ExpectedGeneration uint64   `json:"expected_generation"`
	Algorithm          string   `json:"algorithm"`
	Renews             string   `json:"renews,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	IPAddresses        []string `json:"ip_addresses,omitempty"`
	Organization       string   `json:"organization,omitempty"`
	Locality           string   `json:"locality,omitempty"`
	Province           string   `json:"province,omitempty"`
	Country            string   `json:"country,omitempty"`
}

type requestDeleteInput struct {
	ExpectedGeneration uint64 `json:"expected_generation"`
	PublicFingerprint  string `json:"public_fingerprint"`
}

type requestOutput struct {
	Generation uint64      `json:"generation"`
	Request    requestItem `json:"request"`
}

// The key kinds a page may ask for. The pages offer the first two.
var requestAlgorithms = []string{"ec-p256", "rsa-2048", "ec-p384", "rsa-3072", "rsa-4096"}

// requestEndpoint makes a request (POST /api/requests/create) or gives one up
// with its key (POST /api/requests/delete). Giving one up deletes a key, so it
// needs a fresh code, as deleting a certificate with a key does (C111).
func (g *gate) requestEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	if !signedIn {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if !g.post(w, r) {
		return
	}
	if r.URL.Path == "/api/requests/delete" {
		var input requestDeleteInput
		if !readJSON(w, r, &input) {
			return
		}
		if input.ExpectedGeneration == 0 || !publicinventory.ValidFingerprint(input.PublicFingerprint) {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if !s.isFresh(g.now()) {
			needFresh(w)
			return
		}
		generation, err := g.certificates.DeleteRequest(input.ExpectedGeneration, input.PublicFingerprint)
		if err != nil {
			inventoryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"generation": generation, "deleted": true})
		return
	}
	var input requestInput
	if !readJSON(w, r, &input) {
		return
	}
	params, ok := g.requestParams(w, input)
	if !ok {
		return
	}
	// Making an RSA key takes a moment: one at a time, like a password check.
	if !g.slot(r) {
		http.Error(w, "Rootwell is busy. Try again in a moment.", http.StatusServiceUnavailable)
		return
	}
	csr, key, _, err := csrworkbench.GenerateKept(input.Algorithm, params)
	g.release()
	defer clear(key)
	if err != nil {
		http.Error(w, "These names cannot go into a request.", http.StatusBadRequest)
		return
	}
	if !g.stillReady(r, s) || r.Context().Err() != nil {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	request, generation, err := g.certificates.AddRequest(input.ExpectedGeneration, csr, key, input.Renews)
	if err != nil {
		inventoryError(w, err)
		return
	}
	if !g.stillReady(r, s) || r.Context().Err() != nil {
		http.Error(w, "Request outcome uncertain; sign in and refresh before retrying.", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusCreated, requestOutput{Generation: generation, Request: requestItems([]certstore.Request{request})[0]})
}

// requestParams checks a request's input and, for a renewal, takes the names
// and organization from the saved certificate. It answers the refusal itself.
func (g *gate) requestParams(w http.ResponseWriter, input requestInput) (csrworkbench.Params, bool) {
	bad := func() (csrworkbench.Params, bool) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return csrworkbench.Params{}, false
	}
	if input.ExpectedGeneration == 0 || !slices.Contains(requestAlgorithms, input.Algorithm) {
		return bad()
	}
	if input.Renews == "" {
		params := csrworkbench.Params{Organization: input.Organization, Locality: input.Locality, Province: input.Province, Country: input.Country}
		// The request checks the names: at most 32 DNS names and 8 addresses.
		params.DNSNames, params.IPAddresses = input.DNSNames, input.IPAddresses
		return params, true
	}
	if !publicinventory.ValidFingerprint(input.Renews) || len(input.DNSNames)+len(input.IPAddresses) != 0 || input.Organization != "" || input.Locality != "" || input.Province != "" || input.Country != "" {
		return bad()
	}
	records, _, err := g.certificates.List()
	if err != nil {
		inventoryError(w, err)
		return csrworkbench.Params{}, false
	}
	i := slices.IndexFunc(records, func(r publicinventory.Record) bool { return r.Fingerprint == input.Renews })
	if i < 0 {
		inventoryError(w, certstore.ErrNotFound)
		return csrworkbench.Params{}, false
	}
	if records[i].ReplacedBy != "" {
		inventoryError(w, certstore.ErrReplaced)
		return csrworkbench.Params{}, false
	}
	c, err := x509.ParseCertificate(records[i].DER)
	if err != nil || c.IsCA || len(c.DNSNames)+len(c.IPAddresses) == 0 {
		inventoryError(w, certstore.ErrCannotReplace)
		return csrworkbench.Params{}, false
	}
	params := csrworkbench.Params{DNSNames: append([]string{}, c.DNSNames...)}
	for _, ip := range c.IPAddresses {
		params.IPAddresses = append(params.IPAddresses, ip.String())
	}
	// The common name stays when it is one of the names. Organizational
	// units are left out: public providers no longer accept them.
	if name := c.Subject.CommonName; name != "" && (slices.Contains(c.DNSNames, name) || slices.Contains(params.IPAddresses, name)) {
		params.CommonName = name
	}
	first := func(values []string) string {
		if len(values) == 0 {
			return ""
		}
		return values[0]
	}
	params.Organization, params.Locality, params.Province, params.Country =
		first(c.Subject.Organization), first(c.Subject.Locality), first(c.Subject.Province), first(c.Subject.Country)
	return params, true
}
