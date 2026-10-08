package inventorystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeplan"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
)

var ErrAccountExists = errors.New("a staging account key is already prepared")

// AccountStatus is public metadata, never an account signer or enrollment token.
type AccountStatus struct {
	State       string `json:"state"`
	Fingerprint string `json:"fingerprint"`
	PreparedAt  string `json:"prepared_at"`
}

type accountPayload struct {
	Provider   string `json:"provider"`
	State      string `json:"state"`
	PreparedAt string `json:"prepared_at"`
	PrivateKey []byte `json:"private_key"`
}

func accountID() []byte {
	id := sha256.Sum256([]byte("rootwell.acme-account.v1:" + acmeplan.Provider))
	return id[:]
}

func accountKey(key, id []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, id, "rootwell.acme-account-key.v1:"+acmeplan.Provider, 32)
}

// ReadStagingAccount validates the complete image, including certificate keys.
func ReadStagingAccount(key, id, image []byte) (AccountStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return AccountStatus{}, 0, err
	}
	s, err := accountStatus(key, id, m)
	if err != nil {
		return AccountStatus{}, 0, err
	}
	return s, m.Generation, nil
}

func accountStatus(key, id []byte, m manifest) (AccountStatus, error) {
	if len(m.ACMEAccounts) == 0 {
		return AccountStatus{State: "not-prepared"}, nil
	}
	if len(m.ACMEAccounts) != 1 {
		return AccountStatus{}, ErrInvalid
	}
	item := m.ACMEAccounts[0]
	if !bytes.Equal(item.ID, accountID()) || item.Generation < 2 || item.Generation > m.Generation || len(item.Ciphertext) > 2048 {
		return AccountStatus{}, ErrInvalid
	}
	k, err := accountKey(key, id)
	if err != nil {
		return AccountStatus{}, ErrInvalid
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	if err != nil {
		return AccountStatus{}, ErrInvalid
	}
	defer clear(plain)
	var p accountPayload
	defer func() { clear(p.PrivateKey) }()
	if !strictJSON(plain, &p) || p.Provider != acmeplan.Provider || p.State != "key-prepared" || len(p.PrivateKey) == 0 || len(p.PrivateKey) > 512 {
		return AccountStatus{}, ErrInvalid
	}
	at, err := time.Parse(time.RFC3339, p.PreparedAt)
	if err != nil || at.Year() < 2020 || at.Year() > 9999 || at.UTC().Format("2006-01-02T15:04:05Z") != p.PreparedAt {
		return AccountStatus{}, ErrInvalid
	}
	parsed, err := x509.ParsePKCS8PrivateKey(p.PrivateKey)
	if err != nil {
		return AccountStatus{}, ErrInvalid
	}
	signer, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || signer.Curve != elliptic.P256() {
		return AccountStatus{}, ErrInvalid
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(signer)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, p.PrivateKey) {
		return AccountStatus{}, ErrInvalid
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return AccountStatus{}, ErrInvalid
	}
	sum := sha256.Sum256(pub)
	hexID := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 32)
	for i := range parts {
		parts[i] = hexID[i*2 : i*2+2]
	}
	return AccountStatus{State: p.State, Fingerprint: strings.Join(parts, ":"), PreparedAt: p.PreparedAt}, nil
}

// PrepareStagingAccount creates one signer, with no network or terms authority.
// The caller must atomically commit the result. An existing key is never replaced.
func PrepareStagingAccount(key, id, image []byte, expected uint64) ([]byte, AccountStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, AccountStatus{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, AccountStatus{}, 0, ErrStaleGeneration
	}
	if len(m.ACMEAccounts) != 0 {
		return nil, AccountStatus{}, 0, ErrAccountExists
	}
	if m.Generation >= maxGeneration || len(m.History) >= maxHistory {
		return nil, AccountStatus{}, 0, ErrLimit
	}
	at := time.Now().UTC()
	if at.Year() < 2020 || at.Year() > 9999 {
		return nil, AccountStatus{}, 0, ErrInvalid
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, AccountStatus{}, 0, ErrInvalid
	}
	private, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, AccountStatus{}, 0, ErrInvalid
	}
	defer clear(private)
	// Secret serialization is only an internal encryption boundary, not output.
	plain, err := json.Marshal(accountPayload{Provider: acmeplan.Provider, State: "key-prepared", PreparedAt: at.Format("2006-01-02T15:04:05Z"), PrivateKey: private}) // #nosec G117 -- immediately AES-GCM sealed below; owned plaintext cleared and never logged or returned
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
	if err := addEvent(key, &m, "acme-key-prepared", []string{status.Fingerprint}); err != nil {
		return nil, AccountStatus{}, 0, err
	}
	result, err := encode(key, m)
	if err != nil {
		return nil, AccountStatus{}, 0, err
	}
	verified, generation, err := ReadStagingAccount(key, id, result)
	if err != nil {
		return nil, AccountStatus{}, 0, err
	}
	return result, verified, generation, nil
}
