package inventorystore

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	"github.com/denyfirst/rootwell/internal/acmecertrequest"
	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
)

// CertificateRequestStatus contains no key, CSR, URL or issuance authority.
type CertificateRequestStatus struct {
	Prepared    bool   `json:"prepared"`
	Fingerprint string `json:"fingerprint"`
	PreparedAt  string `json:"prepared_at"`
}

type certificateRequestPayload struct {
	State                  string   `json:"state"`
	PreparedAt             string   `json:"prepared_at"`
	AccountFingerprint     string   `json:"account_fingerprint"`
	Order                  string   `json:"order"`
	Names                  []string `json:"names"`
	PrivateKey             []byte   `json:"private_key"`
	CSR                    []byte   `json:"csr"`
	CertificateFingerprint string   `json:"certificate_fingerprint,omitempty"`
	PreparedGeneration     uint64   `json:"prepared_generation,omitempty"`
}

func certificateRequestID() []byte {
	sum := sha256.Sum256([]byte("rootwell.acme-certificate-request.v1"))
	return sum[:]
}
func certificateRequestKey(key, id []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, id, "rootwell.acme-certificate-request-key.v1", 32)
}

func certificateRequestStatus(key, id []byte, m manifest) (CertificateRequestStatus, error) {
	p, status, err := openCertificateRequest(key, id, m)
	clear(p.PrivateKey)
	return status, err
}

// Owned private bytes are cleared by the caller on success, here on refusal.
func openCertificateRequest(key, id []byte, m manifest) (certificateRequestPayload, CertificateRequestStatus, error) {
	bad := func() (certificateRequestPayload, CertificateRequestStatus, error) {
		return certificateRequestPayload{}, CertificateRequestStatus{}, ErrInvalid
	}
	if len(m.ACMECertificateRequests) == 0 {
		return certificateRequestPayload{}, CertificateRequestStatus{}, nil
	}
	if len(m.ACMECertificateRequests) != 1 {
		return bad()
	}
	item := m.ACMECertificateRequests[0]
	if !bytes.Equal(item.ID, certificateRequestID()) || item.Generation < 4 || item.Generation > m.Generation || len(item.Ciphertext) == 0 || len(item.Ciphertext) > 8192 {
		return bad()
	}
	k, err := certificateRequestKey(key, id)
	if err != nil {
		return bad()
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	if err != nil {
		return bad()
	}
	defer clear(plain)
	var p certificateRequestPayload
	valid := false
	defer func() {
		if !valid {
			clear(p.PrivateKey)
		}
	}()
	if !strictJSON(plain, &p) || (p.State != "key-prepared" && p.State != "key-transferred") || !acmeorder.Time(p.PreparedAt) {
		return bad()
	}
	order, err := openOrder(key, id, m)
	if err != nil || !acmeorder.ValidationStarted(order.State) || order.URL != p.Order || !slices.Equal(p.Names, order.Domains) || p.AccountFingerprint != order.Fingerprint || p.PreparedAt < order.Started || p.PreparedAt >= order.Expires {
		return bad()
	}
	private := p.PrivateKey
	if p.State == "key-transferred" {
		if len(m.ACMEIssuances) != 1 || len(private) != 0 || p.PreparedGeneration < 4 || p.PreparedGeneration >= item.Generation {
			return bad()
		}
		material, materialErr := completionMaterial(key, id, m, p.CertificateFingerprint)
		if materialErr != nil {
			return bad()
		}
		private = material.PrivateKey
		defer clear(private)
	} else if p.CertificateFingerprint != "" || p.PreparedGeneration != 0 {
		return bad()
	}
	summary, err := acmecertrequest.Check(private, p.CSR, p.Names)
	if err != nil || summary.PublicFingerprint == p.AccountFingerprint {
		return bad()
	}
	valid = true
	return p, CertificateRequestStatus{Prepared: true, Fingerprint: summary.PublicFingerprint, PreparedAt: p.PreparedAt}, nil
}

func ReadStagingCertificateRequest(key, id, image []byte) (CertificateRequestStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return CertificateRequestStatus{}, 0, err
	}
	s, err := certificateRequestStatus(key, id, m)
	if err != nil {
		return CertificateRequestStatus{}, 0, err
	}
	return s, m.Generation, nil
}

// PrepareStagingCertificateRequest does no I/O. Its complete-image result must
// be committed atomically under the caller's private revision/permission lock.
func PrepareStagingCertificateRequest(key, id, image []byte, expected uint64) ([]byte, CertificateRequestStatus, uint64, error) {
	return prepareStagingCertificateRequestAt(key, id, image, expected, time.Now().UTC())
}

func prepareStagingCertificateRequestAt(key, id, image []byte, expected uint64, at time.Time) ([]byte, CertificateRequestStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, CertificateRequestStatus{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, CertificateRequestStatus{}, 0, ErrStaleGeneration
	}
	order, err := openOrder(key, id, m)
	now := at.UTC().Format("2006-01-02T15:04:05Z")
	if err != nil || !acmeorder.Time(now) || order.State != "domain-verified" || order.Expires <= now || order.CheckedAt > now || len(m.ACMECertificateRequests) != 0 || len(m.ACMEIssuances) != 0 {
		return nil, CertificateRequestStatus{}, 0, ErrInvalid
	}
	if m.Generation >= maxGeneration || len(m.History) >= maxHistory {
		return nil, CertificateRequestStatus{}, 0, ErrLimit
	}
	private, csr, summary, err := acmecertrequest.Create(order.Domains)
	defer clear(private)
	if err != nil || summary.PublicFingerprint == order.Fingerprint {
		return nil, CertificateRequestStatus{}, 0, ErrInvalid
	}
	p := certificateRequestPayload{State: "key-prepared", PreparedAt: now, AccountFingerprint: order.Fingerprint, Order: order.URL, Names: slices.Clone(order.Domains), PrivateKey: private, CSR: csr}
	plain, err := json.Marshal(p) // #nosec G117 -- purpose-separated AES-GCM immediately below; owned secret plaintext cleared, never returned or logged
	defer clear(plain)
	if err != nil || len(plain) > 8192-64 {
		return nil, CertificateRequestStatus{}, 0, ErrInvalid
	}
	k, err := certificateRequestKey(key, id)
	if err != nil {
		return nil, CertificateRequestStatus{}, 0, ErrInvalid
	}
	defer clear(k)
	m.Generation++
	item := sealedRecord{ID: certificateRequestID(), Generation: m.Generation}
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
	if err != nil {
		return nil, CertificateRequestStatus{}, 0, ErrInvalid
	}
	m.ACMECertificateRequests = []sealedRecord{item}
	if err := addEvent(key, &m, "acme-certificate-key-prepared", []string{summary.PublicFingerprint}); err != nil {
		return nil, CertificateRequestStatus{}, 0, err
	}
	next, err := encode(key, m)
	if err != nil {
		return nil, CertificateRequestStatus{}, 0, err
	}
	status, gen, err := ReadStagingCertificateRequest(key, id, next)
	if err != nil {
		return nil, CertificateRequestStatus{}, 0, err
	}
	return next, status, gen, nil
}
