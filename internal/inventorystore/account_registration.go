package inventorystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
)

type accountRegistration struct {
	State        string `json:"state"`
	Terms        string `json:"terms"`
	StartedAt    string `json:"started_at"`
	AccountURL   string `json:"account_url,omitempty"`
	RegisteredAt string `json:"registered_at,omitempty"`
}

const accountOrigin = "https://acme-staging-v02.api.letsencrypt.org"

// ValidStagingTermsURL is a conservative link policy, not terms-document trust.
// It has no URL fetching capability and rejects queries/escapes/credentials.
func ValidStagingTermsURL(value string) bool {
	const prefix = "https://letsencrypt.org/documents/"
	if len(value) > 1024 || !strings.HasPrefix(value, prefix) {
		return false
	}
	name := strings.TrimPrefix(value, prefix)
	if len(name) == 0 || strings.HasPrefix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func validAccountURL(value string) bool {
	const prefix = accountOrigin + "/acme/acct/"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	number := strings.TrimPrefix(value, prefix)
	if len(number) == 0 || len(number) > 64 || number[0] == '0' {
		return false
	}
	for _, c := range number {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func validAccountTime(value string) bool {
	at, err := time.Parse(time.RFC3339, value)
	return err == nil && at.Year() >= 2020 && at.Year() <= 9999 && at.UTC().Format("2006-01-02T15:04:05Z") == value
}

func validRegistration(r *accountRegistration, prepared string) bool {
	if r == nil {
		return true
	}
	if !ValidStagingTermsURL(r.Terms) || !validAccountTime(r.StartedAt) || r.StartedAt < prepared {
		return false
	}
	switch r.State {
	case "registration-pending":
		return r.AccountURL == "" && r.RegisteredAt == ""
	case "registered":
		return validAccountURL(r.AccountURL) && validAccountTime(r.RegisteredAt) && r.RegisteredAt >= r.StartedAt
	default:
		return false
	}
}

func openAccountPayload(key, id []byte, m manifest) (accountPayload, error) {
	if len(m.ACMEAccounts) != 1 {
		return accountPayload{}, ErrInvalid
	}
	k, err := accountKey(key, id)
	if err != nil {
		return accountPayload{}, ErrInvalid
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, m.ACMEAccounts[0]), m.ACMEAccounts[0].Ciphertext)
	if err != nil {
		return accountPayload{}, ErrInvalid
	}
	defer clear(plain)
	var p accountPayload
	if !strictJSON(plain, &p) {
		clear(p.PrivateKey)
		return accountPayload{}, ErrInvalid
	}
	return p, nil // caller has already authenticated the complete image
}

func sealRegistration(key, id []byte, m manifest, p accountPayload, action string) ([]byte, AccountStatus, uint64, error) {
	if m.Generation >= maxGeneration || len(m.History) >= maxHistory {
		return nil, AccountStatus{}, 0, ErrLimit
	}
	plain, err := json.Marshal(p) // #nosec G117 -- internal plaintext immediately purpose-separated AES-GCM sealed; cleared, not output/logged
	if err != nil {
		return nil, AccountStatus{}, 0, ErrInvalid
	}
	defer clear(plain)
	k, err := accountKey(key, id)
	if err != nil {
		return nil, AccountStatus{}, 0, ErrInvalid
	}
	defer clear(k)
	m.Generation++
	item := sealedRecord{ID: accountID(), Generation: m.Generation}
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
	if err != nil {
		return nil, AccountStatus{}, 0, ErrInvalid
	}
	m.ACMEAccounts = []sealedRecord{item}
	status, err := accountStatus(key, id, m)
	if err != nil {
		return nil, AccountStatus{}, 0, err
	}
	if err := addEvent(key, &m, action, []string{status.Fingerprint}); err != nil {
		return nil, AccountStatus{}, 0, err
	}
	result, err := encode(key, m)
	if err != nil {
		return nil, AccountStatus{}, 0, err
	}
	verified, gen, err := ReadStagingAccount(key, id, result)
	if err != nil {
		return nil, AccountStatus{}, 0, err
	}
	return result, verified, gen, nil
}

// BeginStagingRegistration persists intent before giving any network authority.
// At least one completion event/generation is reserved while intent is pending.
func BeginStagingRegistration(key, id, image []byte, expected uint64, terms string) ([]byte, AccountStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, AccountStatus{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, AccountStatus{}, 0, ErrStaleGeneration
	}
	if !ValidStagingTermsURL(terms) || len(m.ACMEAccounts) != 1 {
		return nil, AccountStatus{}, 0, ErrInvalid
	}
	p, err := openAccountPayload(key, id, m)
	if err != nil {
		return nil, AccountStatus{}, 0, err
	}
	defer clear(p.PrivateKey)
	if p.Registration != nil {
		return nil, AccountStatus{}, 0, ErrAccountExists
	}
	if m.Generation > maxGeneration-2 || len(m.History) > maxHistory-2 {
		return nil, AccountStatus{}, 0, ErrLimit
	}
	p.Registration = &accountRegistration{State: "registration-pending", Terms: terms, StartedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z")}
	return sealRegistration(key, id, m, p, "acme-registration-started")
}

// FinishStagingRegistration records only a strictly validated account URL or a
// confirmed absent account. The original key is preserved in either case.
func FinishStagingRegistration(key, id, image []byte, expected uint64, accountURL string, absent bool) ([]byte, AccountStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, AccountStatus{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, AccountStatus{}, 0, ErrStaleGeneration
	}
	p, err := openAccountPayload(key, id, m)
	if err != nil {
		return nil, AccountStatus{}, 0, err
	}
	defer clear(p.PrivateKey)
	if p.Registration == nil || p.Registration.State != "registration-pending" || (absent && accountURL != "") || (!absent && !validAccountURL(accountURL)) {
		return nil, AccountStatus{}, 0, ErrInvalid
	}
	action := "acme-account-registered"
	if absent {
		p.Registration = nil
		action = "acme-account-absent"
	} else {
		p.Registration.State = "registered"
		p.Registration.AccountURL = accountURL
		p.Registration.RegisteredAt = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	return sealRegistration(key, id, m, p, action)
}

// WithPendingStagingAccount lends a signer only for an authenticated pending
// account at the exact generation. It is never a listing/export/reveal API.
func WithPendingStagingAccount(key, id, image []byte, expected uint64, use func(crypto.Signer, string) error) error {
	m, _, err := decode(key, id, image)
	if err != nil {
		return err
	}
	if expected == 0 || expected != m.Generation {
		return ErrStaleGeneration
	}
	p, err := openAccountPayload(key, id, m)
	if err != nil {
		return err
	}
	defer clear(p.PrivateKey)
	if use == nil || p.Registration == nil || p.Registration.State != "registration-pending" {
		return ErrInvalid
	}
	parsed, err := x509.ParsePKCS8PrivateKey(p.PrivateKey)
	if err != nil {
		return ErrInvalid
	}
	signer, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return ErrInvalid
	}
	return use(signer, p.Registration.Terms)
}
