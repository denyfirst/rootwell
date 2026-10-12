package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/acmestaging"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/inventorystore"
)

type orderConnect func(context.Context, func() bool, crypto.Signer, string, string, []string, func(string) error) (acmeorder.Instructions, error)
type validationConnect func(context.Context, func() bool, crypto.Signer, string, acmeorder.Instructions, []string, bool) (acmeorder.Validation, error)
type certificateConnect func(context.Context, func() bool, crypto.Signer, string, string, string, []string, []byte, []byte, bool) (acmestaging.CertificateObservation, error)
type orderInput struct {
	Password string
	Expected uint64
	Names    []string
}

func readOrderInput(w http.ResponseWriter, r *http.Request, mode string) (orderInput, bool) {
	bad := func() (orderInput, bool) { return orderInput{}, false }
	if mode != "status" && mode != "start" && mode != "resume" && mode != "ack" && mode != "validate" && mode != "refresh" && mode != "prepare-key" && mode != "issue" && mode != "certificate-refresh" {
		return bad()
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return bad()
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	defer clear(body)
	if err != nil || !utf8.Valid(body) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(body))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return bad()
	}
	seen := map[string]bool{}
	input := orderInput{}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return bad()
		}
		seen[name] = true
		switch name {
		case "provider":
			var value string
			if d.Decode(&value) != nil || value != acmeplan.Provider {
				return bad()
			}
		case "confirm":
			var value bool
			if mode == "status" || d.Decode(&value) != nil || !value {
				return bad()
			}
		case "password":
			var value *string
			if mode == "status" || d.Decode(&value) != nil || value == nil || len(*value) == 0 || len(*value) > 256 {
				return bad()
			}
			input.Password = *value
		case "expected_generation":
			var value *uint64
			if mode == "status" || d.Decode(&value) != nil || value == nil || *value < 1 || *value > 1_000_000 {
				return bad()
			}
			input.Expected = *value
		case "domains":
			var value []string
			if mode != "start" || d.Decode(&value) != nil {
				return bad()
			}
			var ok bool
			input.Names, ok = acmeorder.Names(value)
			if !ok {
				return bad()
			}
		default:
			return bad()
		}
	}
	token, err = d.Token()
	count := 4
	if mode == "status" {
		count = 1
	}
	if mode == "start" {
		count = 5
	}
	if err != nil || token != json.Delim('}') || len(seen) != count || !seen["provider"] || (mode != "status" && (!seen["password"] || !seen["confirm"] || !seen["expected_generation"])) || (mode == "start" && !seen["domains"]) {
		return bad()
	}
	_, err = d.Token()
	if err != io.EOF {
		return bad()
	}
	return input, true
}

type orderOutput struct {
	Schema     string `json:"schema_version"`
	Provider   string `json:"provider"`
	Generation uint64 `json:"generation"`
	inventorystore.OrderStatus
	Network        bool                                    `json:"network_used"`
	Saved          bool                                    `json:"saved"`
	DomainVerified bool                                    `json:"domain_verified"`
	CanIssue       bool                                    `json:"can_issue"`
	CertificateKey inventorystore.CertificateRequestStatus `json:"certificate_key"`
	Issuance       inventorystore.IssuanceStatus           `json:"issuance"`
}

func (g *gate) acmeOrderEndpoint(w http.ResponseWriter, r *http.Request, s session, signedIn bool) {
	defer clear(s.dataKey[:])
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !signedIn {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if s.setup || !g.sameOrigin(r) || r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	mode := strings.TrimPrefix(r.URL.Path, "/api/acme/order/")
	input, ok := readOrderInput(w, r, mode)
	defer func() { input.Password = "" }()
	if !ok {
		http.Error(w, "invalid manual DNS request", http.StatusBadRequest)
		return
	}
	if runtime.GOOS != "linux" || !acmestaging.Available() {
		http.Error(w, "Manual DNS orders require Linux or Linux Docker.", http.StatusServiceUnavailable)
		return
	}
	if !s.inventoryReady {
		http.Error(w, "Initialize the encrypted store and full recovery first.", http.StatusConflict)
		return
	}
	if mode != "status" {
		// Extend only this response, not the server's default slow-client
		// budget. The entire operation is bounded separately from CA I/O.
		if http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30*time.Second)) != nil {
			http.Error(w, "bounded response unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if !g.startDerivation() {
		http.Error(w, "another key or password check is running", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-g.derive }()
	permit := func() bool {
		current, ready := g.currentSession(r)
		defer clear(current.dataKey[:])
		return ready && !current.setup && current.revision == s.revision && r.Context().Err() == nil
	}
	if !permit() {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	status, certificateKey, issuance, gen, err := instanceaccess.ReadStagingOrderLifecycle(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
	if err != nil {
		inventoryError(w, err)
		return
	}
	if mode != "status" {
		certificateAction := mode == "issue" || mode == "certificate-refresh"
		if !certificateAction && issuance.State != "not-started" {
			http.Error(w, "Issuance already started. Read saved status; do not repeat DNS validation or prepare another key.", http.StatusConflict)
			return
		}
		if gen != input.Expected {
			http.Error(w, "Saved status changed. Refresh first.", http.StatusConflict)
			return
		}
		if certificateAction && (status.State != "domain-verified" || !certificateKey.Prepared || status.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") || (issuance.Expires != "" && issuance.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z")) || (mode == "issue" && issuance.State != "not-started") || (mode == "certificate-refresh" && (issuance.State == "not-started" || issuance.State == "certificate-saved" || issuance.State == "saved-certificate-deleted"))) {
			http.Error(w, "Read the saved request first. Issuance uses one prepared key once; completed requests remain closed.", http.StatusConflict)
			return
		}
		if mode == "prepare-key" && (status.State != "domain-verified" || certificateKey.Prepared || status.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z")) {
			http.Error(w, "Confirm unexpired CA verification first; an existing certificate key is never replaced.", http.StatusConflict)
			return
		}
		if (mode == "start" && status.State != "not-started") || (mode == "resume" && status.State != "order-known" && status.State != "dns-ready" && status.State != "dns-acknowledged") || (mode == "ack" && status.State != "dns-ready") || (mode == "validate" && status.State != "dns-acknowledged") || (mode == "refresh" && !acmeorder.ValidationStarted(status.State)) {
			http.Error(w, "This action is not available for the saved order. Refresh status; do not create another order.", http.StatusConflict)
			return
		}
		if !g.allowAttempt() {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		setup, err := instanceaccess.Authenticate(g.accessPath, input.Password)
		input.Password = ""
		if err != nil || setup {
			if errors.Is(err, instanceaccess.ErrWrongPassword) {
				http.Error(w, "password not accepted", http.StatusUnauthorized)
			} else {
				http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		if !permit() {
			http.Error(w, "session no longer available", http.StatusUnauthorized)
			return
		}
		if mode == "prepare-key" {
			certificateKey, gen, err = instanceaccess.PrepareStagingCertificateRequest(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, gen, permit)
		} else if mode == "ack" {
			status, gen, err = instanceaccess.AcknowledgeStagingDNS(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, gen, permit)
		} else {
			account, _, accountErr := instanceaccess.ReadStagingAccount(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
			if accountErr != nil || account.Registration != "registered" {
				http.Error(w, "Register the saved staging account first.", http.StatusConflict)
				return
			}
			if !g.startRegistrationProvider(false) {
				http.Error(w, "Wait 30 seconds between provider operations.", http.StatusTooManyRequests)
				return
			}
			defer func() { g.mu.Lock(); g.directoryBusy = false; g.mu.Unlock() }()
			if certificateAction {
				connect := g.certificateConnect
				if connect == nil {
					connect = acmestaging.Certificate
				}
				issuance, gen, err = instanceaccess.RunStagingCertificate(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, gen, mode == "certificate-refresh", permit, func(signer crypto.Signer, account, order, expires string, names []string, private, csr []byte, readOnly bool) (acmestaging.CertificateObservation, error) {
					return connect(r.Context(), permit, signer, account, order, expires, names, private, csr, readOnly)
				})
			} else if mode == "validate" || mode == "refresh" {
				connect := g.validationConnect
				if connect == nil {
					connect = acmestaging.DNSValidation
				}
				status, gen, err = instanceaccess.RunStagingValidation(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, gen, mode == "refresh", permit, func(signer crypto.Signer, account string, saved acmeorder.Instructions, names []string, refresh bool) (acmeorder.Validation, error) {
					return connect(r.Context(), permit, signer, account, saved, names, refresh)
				})
			} else {
				connect := g.orderConnect
				if connect == nil {
					connect = acmestaging.DNSOrder
				}
				status, gen, err = instanceaccess.RunStagingOrder(g.accessPath, s.dataKey[:], s.installationID[:], s.revision, gen, input.Names, mode == "resume", permit, func(signer crypto.Signer, account, order string, names []string, checkpoint func(string) error) (acmeorder.Instructions, error) {
					return connect(r.Context(), permit, signer, account, order, names, checkpoint)
				})
			}
		}
		if err != nil || !permit() {
			http.Error(w, "Outcome not confirmed. Refresh saved status. Continue only the saved order and key; do not resend or create replacements. A sent request cannot be undone.", http.StatusServiceUnavailable)
			return
		}
	}
	// Re-read the preparation from the same final order snapshot. A concurrent
	// external write cannot produce mixed-generation key/order capability flags.
	finalOrder, finalKey, finalIssuance, finalGen, err := instanceaccess.ReadStagingOrderLifecycle(g.accessPath, s.dataKey[:], s.installationID[:], s.revision)
	if err != nil || finalGen != gen {
		http.Error(w, "Saved status changed. Refresh first.", http.StatusConflict)
		return
	}
	status, certificateKey = finalOrder, finalKey
	issuance = finalIssuance
	if !permit() {
		http.Error(w, "session no longer available", http.StatusUnauthorized)
		return
	}
	if status.Domains == nil {
		status.Domains = []string{}
	}
	if status.Records == nil {
		status.Records = []acmeorder.TXT{}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	verified := status.State == "domain-verified" && status.Expires > time.Now().UTC().Format("2006-01-02T15:04:05Z")
	_ = json.NewEncoder(w).Encode(orderOutput{Schema: "rootwell.acme.manual-dns.v5", Provider: acmeplan.Provider, Generation: gen, OrderStatus: status, Network: mode == "start" || mode == "resume" || mode == "validate" || mode == "refresh" || mode == "issue" || mode == "certificate-refresh", Saved: status.State != "not-started", DomainVerified: verified, CanIssue: verified && certificateKey.Prepared && issuance.State == "not-started", CertificateKey: certificateKey, Issuance: issuance})
}
