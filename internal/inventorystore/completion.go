package inventorystore

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/acmecertificate"
	"github.com/denyfirst/rootwell/internal/acmecertrequest"
	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/certificatepair"
	"github.com/denyfirst/rootwell/internal/certinspect"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

// This is authenticated historical acceptance, NOT a current trust verdict.
// The callback/transport receipt itself cannot create this state.
type issuanceCompletion struct {
	TestOnly          bool     `json:"test_only"`
	Fingerprint       string   `json:"fingerprint"`
	SavedAt           string   `json:"saved_at"`
	Generation        uint64   `json:"generation"`
	ChainFingerprints []string `json:"chain_fingerprints"`
	DeletedAt         string   `json:"deleted_at,omitempty"`
}

func certificateFingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return certificateIDFingerprint(h[:])
}

// Fail closed for reservation purposes on malformed intent. Final decode still
// checks ALL bindings before any public status or usable image is returned.
func pendingIssuance(key, id []byte, m manifest) bool {
	if len(m.ACMEIssuances) == 0 {
		return false
	}
	if len(m.ACMEIssuances) != 1 {
		return true
	}
	k, err := issuanceKey(key, id)
	if err != nil {
		return true
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, m.ACMEIssuances[0]), m.ACMEIssuances[0].Ciphertext)
	defer clear(plain)
	var p issuancePayload
	return err != nil || !strictJSON(plain, &p) || p.Completion == nil
}

func completionMaterial(key, id []byte, m manifest, fp string) (materialPayload, error) {
	if !publicinventory.ValidFingerprint(fp) {
		return materialPayload{}, ErrInvalid
	}
	var recordID []byte
	for _, item := range m.Records {
		if certificateIDFingerprint(item.ID) == fp {
			if recordID != nil {
				return materialPayload{}, ErrInvalid
			}
			recordID = item.ID
		}
	}
	if recordID == nil {
		return materialPayload{}, ErrInvalid
	}
	var found *sealedRecord
	for i := range m.Materials {
		if bytes.Equal(m.Materials[i].ID, recordID) {
			if found != nil {
				return materialPayload{}, ErrInvalid
			}
			found = &m.Materials[i]
		}
	}
	if found == nil || found.Generation < 2 || found.Generation > m.Generation {
		return materialPayload{}, ErrInvalid
	}
	p, err := openMaterial(key, id, *found)
	if err != nil || len(p.PrivateKey) == 0 || len(p.Certificates) == 0 || p.MismatchAcknowledged || certificateFingerprint(p.Certificates[0]) != fp {
		clear(p.PrivateKey)
		return materialPayload{}, ErrInvalid
	}
	return p, nil
}

func certificateIDFingerprint(id []byte) string {
	if len(id) != 32 {
		return ""
	}
	hexString := strings.ToUpper(hex.EncodeToString(id))
	parts := make([]string, 32)
	for i := range parts {
		parts[i] = hexString[i*2 : i*2+2]
	}
	return strings.Join(parts, ":")
}

func validateCompletion(key, id []byte, m manifest, p issuancePayload, sealedGeneration uint64) error {
	c := p.Completion
	digest, digestErr := hex.DecodeString(p.RequestFingerprint)
	if digestErr != nil || len(digest) != 32 || strings.ToUpper(p.RequestFingerprint) != p.RequestFingerprint {
		return ErrInvalid
	}
	if c == nil || !c.TestOnly || !publicinventory.ValidFingerprint(c.Fingerprint) || !publicinventory.ValidFingerprint(p.KeyFingerprint) || len(p.RequestFingerprint) != 64 || !acmeorder.Time(c.SavedAt) || c.SavedAt < p.StartedAt || c.Generation <= p.StartedGeneration || c.Generation > sealedGeneration || p.Observation != "" || p.CheckedAt != "" || len(c.ChainFingerprints) < 2 || len(c.ChainFingerprints) > 6 || c.ChainFingerprints[0] != c.Fingerprint {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, fp := range c.ChainFingerprints {
		if !publicinventory.ValidFingerprint(fp) || seen[fp] {
			return ErrInvalid
		}
		seen[fp] = true
	}
	order, err := openOrder(key, id, m)
	if err != nil || order.State != "domain-verified" || order.Fingerprint != p.AccountFingerprint || order.URL != p.Order || !slices.Equal(order.Domains, p.Names) || p.StartedAt < order.CheckedAt || c.SavedAt >= order.Expires {
		return ErrInvalid
	}
	if c.DeletedAt != "" {
		if sealedGeneration <= c.Generation || !acmeorder.Time(c.DeletedAt) || c.DeletedAt < c.SavedAt || len(m.ACMECertificateRequests) != 0 {
			return ErrInvalid
		}
		for _, r := range m.Records {
			if certificateIDFingerprint(r.ID) == c.Fingerprint {
				return ErrInvalid
			}
		}
		return nil
	}
	request, status, err := openCertificateRequest(key, id, m)
	defer clear(request.PrivateKey)
	if err != nil || request.State != "key-transferred" || request.CertificateFingerprint != c.Fingerprint || request.PreparedGeneration >= p.StartedGeneration || status.Fingerprint != p.KeyFingerprint || csrFingerprint(request.CSR) != p.RequestFingerprint || p.StartedAt < request.PreparedAt {
		return ErrInvalid
	}
	material, err := completionMaterial(key, id, m, c.Fingerprint)
	defer clear(material.PrivateKey)
	if err != nil || !completionChainMatches(material.Certificates, c.ChainFingerprints) {
		return ErrInvalid
	}
	for _, item := range m.Materials {
		if certificateIDFingerprint(item.ID) == c.Fingerprint && item.Generation != c.Generation {
			return ErrInvalid
		}
	}
	for _, item := range m.Records {
		if certificateIDFingerprint(item.ID) != c.Fingerprint {
			continue
		}
		plain, err := inventoryseal.Open(key, attachmentContext(id, item), item.Ciphertext)
		defer clear(plain)
		var record payload
		if err != nil || !strictJSON(plain, &record) || record.ImportedAt != c.SavedAt || record.ImportGeneration != c.Generation {
			return ErrInvalid
		}
	}
	if m.ACMECertificateRequests[0].Generation != c.Generation {
		return ErrInvalid
	}
	leaf, _, err := certinspect.Parse(material.Certificates[0])
	if err != nil {
		return ErrInvalid
	}
	names := slices.Clone(leaf.DNSNames)
	slices.Sort(names)
	if leaf.IsCA || !slices.Equal(names, p.Names) {
		return ErrInvalid
	}
	return nil
}

func completionChainMatches(chain [][]byte, fps []string) bool {
	if len(chain) == 0 || len(chain) > 5 || (len(fps) != len(chain) && len(fps) != len(chain)+1) {
		return false
	}
	for i, der := range chain {
		if certificateFingerprint(der) != fps[i] {
			return false
		}
	}
	return true
}

func sealCompletionIntent(key, id []byte, m *manifest, p issuancePayload) error {
	k, err := issuanceKey(key, id)
	if err != nil {
		return ErrInvalid
	}
	defer clear(k)
	plain, err := json.Marshal(p)
	defer clear(plain)
	if err != nil || len(plain) > 8192-64 {
		return ErrLimit
	}
	item := sealedRecord{ID: issuanceID(), Generation: m.Generation}
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
	if err != nil {
		return ErrInvalid
	}
	m.ACMEIssuances = []sealedRecord{item}
	return nil
}

// Completion requires the exact saved request and real independent staging
// acceptance under the caller's private writer lock. No imported trust/result
// flag, supplied private key or receipt checker is a public input.
func FinishStagingIssuance(key, id, image []byte, expected uint64, response [][]byte) ([]byte, IssuanceStatus, uint64, error) {
	next, status, gen, err := finishStagingIssuance(key, id, image, expected, response, time.Now().UTC(), acmecertificate.Check)
	if err != nil {
		return nil, IssuanceStatus{}, 0, err
	}
	m, _, err := decode(key, id, next)
	order, orderErr := openOrder(key, id, m)
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if err != nil || orderErr != nil || !acmeorder.Time(now) || now < status.CheckedAt || now >= order.Expires {
		return nil, IssuanceStatus{}, 0, ErrInvalid
	}
	return next, status, gen, nil
}

// Unexported test seam, never runtime configuration. Production is fixed above.
func finishStagingIssuance(key, id, image []byte, expected uint64, response [][]byte, at time.Time, check func([]byte, []byte, []string, [][]byte, time.Time) (acmecertificate.Result, error)) ([]byte, IssuanceStatus, uint64, error) {
	bad := func(err error) ([]byte, IssuanceStatus, uint64, error) { return nil, IssuanceStatus{}, 0, err }
	m, _, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	if expected == 0 || expected != m.Generation {
		return bad(ErrStaleGeneration)
	}
	p, err := openIssuance(key, id, m)
	order, orderErr := openOrder(key, id, m)
	now := at.UTC().Format("2006-01-02T15:04:05Z")
	if err != nil || orderErr != nil || p.StartedAt == "" || p.Completion != nil || check == nil || !acmeorder.Time(now) || now < p.StartedAt || now < p.CheckedAt || now >= order.Expires || len(response) == 0 || len(response) > 5 {
		return bad(ErrInvalid)
	}
	request, _, err := openCertificateRequest(key, id, m)
	defer clear(request.PrivateKey)
	defer clear(request.CSR)
	if err != nil || request.State != "key-prepared" {
		return bad(ErrInvalid)
	}
	accepted, err := check(request.PrivateKey, request.CSR, p.Names, response, at)
	summary, summaryErr := acmecertrequest.Check(request.PrivateKey, request.CSR, p.Names)
	if err != nil || summaryErr != nil || !accepted.TestOnly || accepted.Fingerprint != certificateFingerprint(response[0]) || accepted.PublicFingerprint != p.KeyFingerprint || accepted.RequestFingerprint != summary.RequestFingerprint || !slices.Equal(accepted.DNSNames, p.Names) || !accepted.EvaluatedAt.Equal(at) || !completionChainMatches(response, accepted.ChainFingerprints) {
		return bad(acmecertificate.ErrInvalid)
	}
	if m.Generation >= maxGeneration || len(m.History) >= maxHistory || len(m.Records) >= maxRecords {
		return bad(ErrLimit)
	}
	for _, r := range m.Records {
		if hmac.Equal(r.ID, mID(response[0])) {
			return bad(publicinventory.ErrDuplicate)
		}
	}
	public := certificatepair.PublicPEM(response)
	r, canonical, err := certificatepair.PrepareBundle(public, request.PrivateKey, nil, "", "", accepted.Fingerprint)
	defer clear(canonical)
	if err != nil || r.KeyStatus != "matched" || !bytes.Equal(canonical, request.PrivateKey) {
		return bad(ErrInvalid)
	}
	m.Generation++
	r.ImportGeneration = m.Generation
	r.ImportedAt = now
	plain, err := json.Marshal(payload{DER: r.DER, ImportedAt: now, ImportGeneration: m.Generation})
	if err != nil {
		return bad(ErrInvalid)
	}
	item := sealedRecord{ID: mID(r.DER), Generation: m.Generation}
	item.Ciphertext, err = inventoryseal.Seal(key, attachmentContext(id, item), plain)
	if err != nil {
		return bad(ErrInvalid)
	}
	m.Records = append(m.Records, item)
	material, err := sealMaterial(key, id, r, canonical, false, m.Generation)
	if err != nil {
		return bad(ErrLimit)
	}
	m.Materials = append(m.Materials, material)
	// MOVE the key: only the matched material owns it in this new image. Old
	// backups/runtime copies are not erased. Keep public CSR/scope tombstone.
	request.State = "key-transferred"
	request.PreparedGeneration = m.ACMECertificateRequests[0].Generation
	request.CertificateFingerprint = r.Fingerprint
	request.PrivateKey = nil
	reqPlain, err := json.Marshal(request) // #nosec G117 -- PrivateKey removed above; public CSR/scope tombstone immediately AES-GCM sealed below, owned plaintext cleared, never output/logged
	defer clear(reqPlain)
	if err != nil {
		return bad(ErrInvalid)
	}
	reqKey, err := certificateRequestKey(key, id)
	if err != nil {
		return bad(ErrInvalid)
	}
	defer clear(reqKey)
	reqItem := sealedRecord{ID: certificateRequestID(), Generation: m.Generation}
	reqItem.Ciphertext, err = inventoryseal.Seal(reqKey, attachmentContext(id, reqItem), reqPlain)
	if err != nil {
		return bad(ErrInvalid)
	}
	m.ACMECertificateRequests = []sealedRecord{reqItem}
	p.CheckedAt = ""
	p.Observation = ""
	p.Completion = &issuanceCompletion{TestOnly: true, Fingerprint: r.Fingerprint, SavedAt: now, Generation: m.Generation, ChainFingerprints: slices.Clone(accepted.ChainFingerprints)}
	if err := sealCompletionIntent(key, id, &m, p); err != nil {
		return bad(err)
	}
	if err := addEvent(key, &m, "acme-certificate-saved", []string{r.Fingerprint}); err != nil {
		return bad(err)
	}
	next, err := encode(key, m)
	if err != nil {
		return bad(err)
	}
	status, gen, err := ReadStagingIssuance(key, id, next)
	if err != nil {
		return bad(err)
	}
	return next, status, gen, nil
}

func deleteCompletion(key, id []byte, m *manifest, fp string) error {
	if len(m.ACMEIssuances) == 0 {
		return nil
	}
	// Record/material already removed by the mutation. Read the sealed payload
	// without attempting the now-incomplete pre-deletion linked-record check.
	k, err := issuanceKey(key, id)
	if err != nil {
		return ErrInvalid
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, m.ACMEIssuances[0]), m.ACMEIssuances[0].Ciphertext)
	defer clear(plain)
	var p issuancePayload
	if err != nil || !strictJSON(plain, &p) {
		return ErrInvalid
	}
	if p.Completion == nil || p.Completion.Fingerprint != fp {
		return nil
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if !acmeorder.Time(now) || now < p.Completion.SavedAt {
		return ErrInvalid
	}
	p.Completion.DeletedAt = now
	m.ACMECertificateRequests = nil
	return sealCompletionIntent(key, id, m, p)
}
