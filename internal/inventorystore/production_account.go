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

	"github.com/denyfirst/rootwell/internal/acmeprofile"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
)

var ErrProductionAccountExists = errors.New("a separate production account key is already prepared")

// No registration, URL, terms, signer export or certificate authority. This
// distinct payload cannot be interpreted as an existing staging registration.
type productionAccountPayload struct {
	Provider   string `json:"provider"`
	State      string `json:"state"`
	PreparedAt string `json:"prepared_at"`
	PrivateKey []byte `json:"private_key"`
}

func productionAccountID() []byte {
	sum := sha256.Sum256([]byte(acmeprofile.Production.Namespace() + ":account-record"))
	return sum[:]
}

func productionAccountKey(key, id []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, id, acmeprofile.Production.Namespace()+":account-key", 32)
}

func ReadProductionAccount(key, id, image []byte) (AccountStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return AccountStatus{}, 0, err
	}
	status, err := productionAccountStatus(key, id, m)
	if err != nil {
		return AccountStatus{}, 0, err
	}
	return status, m.Generation, nil
}

func productionAccountStatus(key, id []byte, m manifest) (AccountStatus, error) {
	bad := func() (AccountStatus, error) { return AccountStatus{}, ErrInvalid }
	if len(m.ProductionACMEAccounts) == 0 {
		return AccountStatus{State: "not-prepared", Registration: "not-registered"}, nil
	}
	if len(m.ProductionACMEAccounts) != 1 {
		return bad()
	}
	item := m.ProductionACMEAccounts[0]
	if !bytes.Equal(item.ID, productionAccountID()) || item.Generation < 2 || item.Generation > m.Generation || len(item.Ciphertext) == 0 || len(item.Ciphertext) > 2048 {
		return bad()
	}
	k, err := productionAccountKey(key, id)
	if err != nil {
		return bad()
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	defer clear(plain)
	var p productionAccountPayload
	defer func() { clear(p.PrivateKey) }()
	if err != nil || !strictJSON(plain, &p) || p.Provider != acmeprofile.Production.Provider() || p.State != "key-prepared" || !validAccountTime(p.PreparedAt) || len(p.PrivateKey) == 0 || len(p.PrivateKey) > 512 {
		return bad()
	}
	parsed, err := x509.ParsePKCS8PrivateKey(p.PrivateKey)
	if err != nil {
		return bad()
	}
	signer, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || signer.Curve != elliptic.P256() {
		return bad()
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(signer)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, p.PrivateKey) {
		return bad()
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return bad()
	}
	sum := sha256.Sum256(pub)
	hexID := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 32)
	for i := range parts {
		parts[i] = hexID[2*i : 2*i+2]
	}
	return AccountStatus{State: p.State, Fingerprint: strings.Join(parts, ":"), PreparedAt: p.PreparedAt, Registration: "not-registered"}, nil
}

// PrepareProductionAccount adds one independently generated local key. Existing
// staging ciphertext is untouched. The caller must atomically publish this
// complete image under its existing writer/revision/permission boundary.
func PrepareProductionAccount(key, id, image []byte, expected uint64) ([]byte, AccountStatus, uint64, error) {
	bad := func(err error) ([]byte, AccountStatus, uint64, error) { return nil, AccountStatus{}, 0, err }
	m, _, err := decode(key, id, image)
	if err != nil {
		return bad(err)
	}
	if expected == 0 || expected != m.Generation {
		return bad(ErrStaleGeneration)
	}
	if len(m.ProductionACMEAccounts) != 0 {
		return bad(ErrProductionAccountExists)
	}
	if m.Generation >= maxGeneration || len(m.History) >= maxHistory {
		return bad(ErrLimit)
	}
	at := time.Now().UTC()
	if at.Year() < 2020 || at.Year() > 9999 || !timingClock(key, id, m, at, nil) {
		return bad(ErrInvalid)
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return bad(ErrInvalid)
	}
	private, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return bad(ErrInvalid)
	}
	defer clear(private)
	plain, err := json.Marshal(productionAccountPayload{Provider: acmeprofile.Production.Provider(), State: "key-prepared", PreparedAt: at.Format(time.RFC3339), PrivateKey: private}) // #nosec G117 -- internal plaintext immediately purpose-separated AES-GCM sealed, cleared and never output/logged
	if err != nil {
		return bad(ErrInvalid)
	}
	defer clear(plain)
	k, err := productionAccountKey(key, id)
	if err != nil {
		return bad(ErrInvalid)
	}
	defer clear(k)
	m.Generation++
	item := sealedRecord{ID: productionAccountID(), Generation: m.Generation}
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
	if err != nil {
		return bad(ErrInvalid)
	}
	m.ProductionACMEAccounts = []sealedRecord{item}
	status, err := productionAccountStatus(key, id, m)
	if err != nil {
		return bad(err)
	}
	if err := addEvent(key, &m, "acme-production-key-prepared", []string{status.Fingerprint}); err != nil {
		return bad(err)
	}
	next, err := encode(key, m)
	if err != nil {
		return bad(err)
	}
	verified, generation, err := ReadProductionAccount(key, id, next)
	if err != nil {
		return bad(err)
	}
	return next, verified, generation, nil
}
