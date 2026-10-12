package inventorystore

import (
	"bytes"
	"crypto"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/keymatch"
)

const issuanceByteReserve = 1 << 20 // conservative headroom, not a pair-save implementation

var ErrIssuanceUncertain = errors.New("certificate operation outcome is uncertain; check the same saved order")

// No key/CSR/URL/CA error or finalization authority is public status evidence.
type IssuanceStatus struct {
	State       string `json:"state"`
	StartedAt   string `json:"started_at"`
	CheckedAt   string `json:"checked_at"`
	Observation string `json:"observation"`
}

type issuancePayload struct {
	StartedAt          string   `json:"started_at"`
	StartedGeneration  uint64   `json:"started_generation"`
	AccountFingerprint string   `json:"account_fingerprint"`
	KeyFingerprint     string   `json:"key_fingerprint"`
	RequestFingerprint string   `json:"request_fingerprint"`
	Order              string   `json:"order"`
	Names              []string `json:"names"`
	CheckedAt          string   `json:"checked_at,omitempty"`
	Observation        string   `json:"observation,omitempty"`
}

// IssuanceAttempt is a process-local, single-use lease, not a serialized field.
// Only a successful FIRST Begin can mint a finalize lease. Restored/reopened
// intent can mint read-only leases only. Copies share the SAME consumed state.
type IssuanceAttempt struct {
	lease *issuanceLease
}

type issuanceLease struct {
	imageHash  [32]byte
	generation uint64
	refresh    bool
	used       atomic.Bool
}

func mintIssuanceAttempt(image []byte, gen uint64, refresh bool) *IssuanceAttempt {
	return &IssuanceAttempt{lease: &issuanceLease{imageHash: sha256.Sum256(image), generation: gen, refresh: refresh}}
}

func issuanceCapacity(m manifest, imageBytes int) bool {
	return m.Generation <= maxGeneration-2 && len(m.History) <= maxHistory-2 && len(m.Records) < maxRecords && imageBytes > 0 && imageBytes <= maxImage-issuanceByteReserve
}

func issuanceID() []byte { h := sha256.Sum256([]byte("rootwell.acme-issuance.v1")); return h[:] }
func issuanceKey(key, id []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, id, "rootwell.acme-issuance-key.v1", 32)
}
func csrFingerprint(csr []byte) string {
	h := sha256.Sum256(csr)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

func openIssuance(key, id []byte, m manifest) (issuancePayload, error) {
	bad := func() (issuancePayload, error) { return issuancePayload{}, ErrInvalid }
	if len(m.ACMEIssuances) == 0 {
		return issuancePayload{}, nil
	}
	if len(m.ACMEIssuances) != 1 || len(m.ACMECertificateRequests) != 1 || len(m.Records) >= maxRecords || len(m.History) >= maxHistory || m.Generation >= maxGeneration {
		return bad()
	}
	item := m.ACMEIssuances[0]
	if !bytes.Equal(item.ID, issuanceID()) || item.Generation > m.Generation || len(item.Ciphertext) == 0 || len(item.Ciphertext) > 8192 {
		return bad()
	}
	k, err := issuanceKey(key, id)
	if err != nil {
		return bad()
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	if err != nil {
		return bad()
	}
	defer clear(plain)
	var p issuancePayload
	if !strictJSON(plain, &p) || !acmeorder.Time(p.StartedAt) || p.StartedGeneration <= m.ACMECertificateRequests[0].Generation || p.StartedGeneration > item.Generation {
		return bad()
	}
	request, status, err := openCertificateRequest(key, id, m)
	defer clear(request.PrivateKey)
	order, orderErr := openOrder(key, id, m)
	if err != nil || orderErr != nil || !status.Prepared || order.State != "domain-verified" || p.StartedAt < status.PreparedAt || p.StartedAt < order.CheckedAt || p.StartedAt >= order.Expires || p.AccountFingerprint != order.Fingerprint || p.Order != order.URL || !slices.Equal(p.Names, order.Domains) || p.KeyFingerprint != status.Fingerprint || p.RequestFingerprint != csrFingerprint(request.CSR) {
		return bad()
	}
	if p.Observation == "" {
		if p.CheckedAt != "" {
			return bad()
		}
	} else if !slices.Contains([]string{"pending", "ready", "processing", "invalid"}, p.Observation) || !acmeorder.Time(p.CheckedAt) || p.CheckedAt < p.StartedAt || p.CheckedAt >= order.Expires {
		return bad()
	}
	return p, nil
}

func publicIssuance(p issuancePayload) IssuanceStatus {
	state := "not-started"
	if p.StartedAt != "" {
		state = "issuance-pending"
	}
	switch p.Observation {
	case "pending", "ready":
		state = "not-issued"
	case "processing":
		state = "awaiting-certificate"
	case "invalid":
		state = "issuance-failed"
	}
	return IssuanceStatus{State: state, StartedAt: p.StartedAt, CheckedAt: p.CheckedAt, Observation: p.Observation}
}

func ReadStagingIssuance(key, id, image []byte) (IssuanceStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return IssuanceStatus{}, 0, err
	}
	p, err := openIssuance(key, id, m)
	if err != nil {
		return IssuanceStatus{}, 0, err
	}
	return publicIssuance(p), m.Generation, nil
}

func sealIssuance(key, id []byte, m manifest, p issuancePayload, action string) ([]byte, IssuanceStatus, uint64, error) {
	if m.Generation >= maxGeneration-1 || len(m.History) >= maxHistory-1 || len(m.Records) >= maxRecords {
		return nil, IssuanceStatus{}, 0, ErrLimit
	}
	k, err := issuanceKey(key, id)
	if err != nil {
		return nil, IssuanceStatus{}, 0, ErrInvalid
	}
	defer clear(k)
	plain, err := json.Marshal(p)
	defer clear(plain)
	if err != nil || len(plain) > 8192-64 {
		return nil, IssuanceStatus{}, 0, ErrInvalid
	}
	m.Generation++
	item := sealedRecord{ID: issuanceID(), Generation: m.Generation}
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
	if err != nil {
		return nil, IssuanceStatus{}, 0, ErrInvalid
	}
	m.ACMEIssuances = []sealedRecord{item}
	if err := addEvent(key, &m, action, []string{p.KeyFingerprint}); err != nil {
		return nil, IssuanceStatus{}, 0, err
	}
	image, err := encode(key, m)
	if err != nil {
		return nil, IssuanceStatus{}, 0, err
	}
	status, gen, err := ReadStagingIssuance(key, id, image)
	if err != nil {
		return nil, IssuanceStatus{}, 0, err
	}
	return image, status, gen, nil
}

// A nil next image on refresh is intentional: the already durable irreversible
// intent covers same-order reads, which grant no issuance/trust verdict. This
// preserves the last completion slot even at the history/nonce limit.
func BeginStagingIssuance(key, id, image []byte, expected uint64, refresh bool) ([]byte, *IssuanceAttempt, IssuanceStatus, uint64, error) {
	return beginStagingIssuanceAt(key, id, image, expected, refresh, time.Now().UTC())
}
func beginStagingIssuanceAt(key, id, image []byte, expected uint64, refresh bool, at time.Time) ([]byte, *IssuanceAttempt, IssuanceStatus, uint64, error) {
	bad := func(err error) ([]byte, *IssuanceAttempt, IssuanceStatus, uint64, error) {
		return nil, nil, IssuanceStatus{}, 0, err
	}
	m, _, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	if expected == 0 || expected != m.Generation {
		return bad(ErrStaleGeneration)
	}
	request, status, err := openCertificateRequest(key, id, m)
	defer clear(request.PrivateKey)
	order, orderErr := openOrder(key, id, m)
	now := at.UTC().Format("2006-01-02T15:04:05Z")
	p, intentErr := openIssuance(key, id, m)
	if err != nil || orderErr != nil || intentErr != nil || !status.Prepared || order.State != "domain-verified" || !acmeorder.Time(now) || now < status.PreparedAt || now < order.CheckedAt || now >= order.Expires || p.CheckedAt > now || p.StartedAt > now {
		return bad(ErrInvalid)
	}
	if refresh {
		if len(m.ACMEIssuances) != 1 {
			return bad(ErrInvalid)
		}
		return nil, mintIssuanceAttempt(image, m.Generation, true), publicIssuance(p), m.Generation, nil
	}
	if len(m.ACMEIssuances) != 0 {
		return bad(ErrInvalid)
	}
	if !issuanceCapacity(m, len(image)) {
		return bad(ErrLimit)
	}
	p = issuancePayload{StartedAt: now, StartedGeneration: m.Generation + 1, AccountFingerprint: order.Fingerprint, KeyFingerprint: status.Fingerprint, RequestFingerprint: csrFingerprint(request.CSR), Order: order.URL, Names: slices.Clone(order.Domains)}
	next, public, gen, err := sealIssuance(key, id, m, p, "acme-issuance-started")
	if err != nil {
		return bad(err)
	}
	return next, mintIssuanceAttempt(next, gen, false), public, gen, nil
}

// The locked caller MUST durably install Begin's image before lending the
// attempt. This pure image layer cannot prove a filesystem commit occurred.
// Scope and direction come from the opaque attempt, never a callback argument.
func WithStagingIssuance(key, id, image []byte, expected uint64, attempt *IssuanceAttempt, use func(crypto.Signer, string, string, string, []string, []byte, []byte, bool) error) error {
	m, _, err := decode(key, id, image)
	if err != nil {
		return err
	}
	if expected == 0 || m.Generation != expected {
		return ErrStaleGeneration
	}
	p, err := openIssuance(key, id, m)
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	order, orderErr := openOrder(key, id, m)
	if err != nil || orderErr != nil || p.StartedAt == "" || use == nil || attempt == nil || attempt.lease == nil || attempt.lease.generation != expected || attempt.lease.imageHash != sha256.Sum256(image) || !acmeorder.Time(now) || p.StartedAt > now || p.CheckedAt > now || order.Expires <= now || attempt.lease.used.Swap(true) {
		return ErrInvalid
	}
	request, _, err := openCertificateRequest(key, id, m)
	if err != nil {
		return ErrInvalid
	}
	defer clear(request.PrivateKey)
	defer clear(request.CSR)
	account, err := openAccountPayload(key, id, m)
	if err != nil {
		return ErrInvalid
	}
	defer clear(account.PrivateKey)
	parsed, err := x509.ParsePKCS8PrivateKey(account.PrivateKey)
	defer keymatch.ClearParsedKey(parsed)
	signer, ok := parsed.(crypto.Signer)
	if err != nil || !ok {
		return ErrInvalid
	}
	if err := use(signer, account.Registration.AccountURL, p.Order, order.Expires, slices.Clone(p.Names), request.PrivateKey, request.CSR, attempt.lease.refresh); err != nil {
		return ErrIssuanceUncertain
	}
	return nil
}

// Only NON-issued observations can be saved here. Certificate receipt/trust/
// pair transfer/provenance require a separate acceptance transaction.
func ObserveStagingIssuance(key, id, image []byte, expected uint64, observation string) ([]byte, IssuanceStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, IssuanceStatus{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, IssuanceStatus{}, 0, ErrStaleGeneration
	}
	p, err := openIssuance(key, id, m)
	order, orderErr := openOrder(key, id, m)
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if err != nil || orderErr != nil || p.StartedAt == "" || !acmeorder.Time(now) || now < p.StartedAt || now < p.CheckedAt || now >= order.Expires || !slices.Contains([]string{"pending", "ready", "processing", "invalid"}, observation) {
		return nil, IssuanceStatus{}, 0, ErrInvalid
	}
	p.CheckedAt, p.Observation = now, observation
	return sealIssuance(key, id, m, p, "acme-issuance-observed")
}
