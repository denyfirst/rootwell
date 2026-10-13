package inventorystore

import (
	"bytes"
	"crypto"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"slices"
	"time"

	"github.com/denyfirst/rootwell/internal/acmeorder"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
)

type OrderStatus struct {
	State   string          `json:"state"`
	Domains []string        `json:"domains"`
	Expires string          `json:"expires"`
	Records []acmeorder.TXT `json:"records"`
}

type orderPayload struct {
	State       string                `json:"state"`
	Fingerprint string                `json:"fingerprint"`
	Started     string                `json:"started"`
	Domains     []string              `json:"domains"`
	URL         string                `json:"url,omitempty"`
	Expires     string                `json:"expires,omitempty"`
	Records     []acmeorder.TXT       `json:"records,omitempty"`
	Validation  *acmeorder.Validation `json:"validation,omitempty"`
	CheckedAt   string                `json:"checked_at,omitempty"`
}

func orderID() []byte { sum := sha256.Sum256([]byte("rootwell.acme-staging-order.v1")); return sum[:] }
func orderKey(key, id []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, id, "rootwell.acme-staging-order-key.v1", 32)
}

func openOrder(key, id []byte, m manifest) (orderPayload, error) {
	if len(m.ACMEOrders) == 0 {
		return orderPayload{State: "not-started", Domains: []string{}}, nil
	}
	if len(m.ACMEOrders) != 1 {
		return orderPayload{}, ErrInvalid
	}
	item := m.ACMEOrders[0]
	if !bytes.Equal(item.ID, orderID()) || item.Generation < 3 || item.Generation > m.Generation || len(item.Ciphertext) > 16384 {
		return orderPayload{}, ErrInvalid
	}
	k, err := orderKey(key, id)
	if err != nil {
		return orderPayload{}, ErrInvalid
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	if err != nil {
		return orderPayload{}, ErrInvalid
	}
	defer clear(plain)
	var p orderPayload
	if !strictJSON(plain, &p) || !acmeorder.CanonicalNames(p.Domains) || !acmeorder.Time(p.Started) {
		return orderPayload{}, ErrInvalid
	}
	status, err := accountStatus(key, id, m)
	if err != nil || status.Registration != "registered" || status.Fingerprint != p.Fingerprint || p.Started < status.PreparedAt {
		return orderPayload{}, ErrInvalid
	}
	account, err := openAccountPayload(key, id, m)
	if err != nil {
		return orderPayload{}, ErrInvalid
	}
	defer clear(account.PrivateKey)
	if p.Started < account.Registration.RegisteredAt {
		return orderPayload{}, ErrInvalid
	}
	if !acmeorder.ValidationStarted(p.State) && (p.Validation != nil || p.CheckedAt != "") {
		return orderPayload{}, ErrInvalid
	}
	switch p.State {
	case "request-pending":
		if p.URL != "" || p.Expires != "" || len(p.Records) != 0 {
			return orderPayload{}, ErrInvalid
		}
	case "order-known":
		if !acmeorder.OrderURL(p.URL, account.Registration.AccountURL) || p.Expires != "" || len(p.Records) != 0 {
			return orderPayload{}, ErrInvalid
		}
	case "dns-ready", "dns-acknowledged", "validation-pending", "validation-waiting", "validation-failed", "domain-verified":
		if !acmeorder.ValidInstructions(acmeorder.Instructions{URL: p.URL, Expires: p.Expires, Records: p.Records}, account.Registration.AccountURL, p.Domains) || p.Expires <= p.Started {
			return orderPayload{}, ErrInvalid
		}
		if p.State == "validation-pending" && (p.Validation != nil || p.CheckedAt != "") {
			return orderPayload{}, ErrInvalid
		}
		if acmeorder.ValidationStarted(p.State) && p.State != "validation-pending" {
			if p.Validation == nil || p.Validation.URL != p.URL || p.Validation.Expires != p.Expires || acmeorder.ValidationState(*p.Validation, p.Domains) != p.State || !acmeorder.Time(p.CheckedAt) || p.CheckedAt < p.Started || p.CheckedAt >= p.Expires {
				return orderPayload{}, ErrInvalid
			}
		}
	default:
		return orderPayload{}, ErrInvalid
	}
	return p, nil
}

func publicOrder(p orderPayload) OrderStatus {
	return OrderStatus{State: p.State, Domains: slices.Clone(p.Domains), Expires: p.Expires, Records: slices.Clone(p.Records)}
}

func ReadStagingOrder(key, id, image []byte) (OrderStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return OrderStatus{}, 0, err
	}
	p, err := openOrder(key, id, m)
	if err != nil {
		return OrderStatus{}, 0, err
	}
	return publicOrder(p), m.Generation, nil
}

func sealOrder(key, id []byte, m manifest, p orderPayload, action string) ([]byte, OrderStatus, uint64, error) {
	if m.Generation >= maxGeneration || len(m.History) >= maxHistory {
		return nil, OrderStatus{}, 0, ErrLimit
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, OrderStatus{}, 0, ErrInvalid
	}
	defer clear(plain)
	k, err := orderKey(key, id)
	if err != nil {
		return nil, OrderStatus{}, 0, ErrInvalid
	}
	defer clear(k)
	m.Generation++
	item := sealedRecord{ID: orderID(), Generation: m.Generation}
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
	if err != nil {
		return nil, OrderStatus{}, 0, ErrInvalid
	}
	m.ACMEOrders = []sealedRecord{item}
	if _, err := openOrder(key, id, m); err != nil {
		return nil, OrderStatus{}, 0, err
	}
	if err := addEvent(key, &m, action, []string{p.Fingerprint}); err != nil {
		return nil, OrderStatus{}, 0, err
	}
	image, err := encode(key, m)
	if err != nil {
		return nil, OrderStatus{}, 0, err
	}
	status, gen, err := ReadStagingOrder(key, id, image)
	if err != nil {
		return nil, OrderStatus{}, 0, err
	}
	return image, status, gen, nil
}

func BeginStagingOrder(key, id, image []byte, expected uint64, names []string) ([]byte, OrderStatus, uint64, error) {
	return beginStagingOrderAt(key, id, image, expected, names, time.Now().UTC())
}

func beginStagingOrderAt(key, id, image []byte, expected uint64, names []string, at time.Time) ([]byte, OrderStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, OrderStatus{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, OrderStatus{}, 0, ErrStaleGeneration
	}
	account, err := accountStatus(key, id, m)
	if err != nil || account.Registration != "registered" || len(m.ACMEOrders) != 0 || !acmeorder.CanonicalNames(names) {
		return nil, OrderStatus{}, 0, ErrInvalid
	}
	// Intent, URI checkpoint and instructions must all fit before network.
	if m.Generation > maxGeneration-3 || len(m.History) > maxHistory-3 {
		return nil, OrderStatus{}, 0, ErrLimit
	}
	p := orderPayload{State: "request-pending", Fingerprint: account.Fingerprint, Started: at.UTC().Format("2006-01-02T15:04:05Z"), Domains: slices.Clone(names)}
	return sealOrder(key, id, m, p, "acme-order-started")
}

func UpdateStagingOrder(key, id, image []byte, expected uint64, url string, info *acmeorder.Instructions, acknowledge bool) ([]byte, OrderStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, OrderStatus{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, OrderStatus{}, 0, ErrStaleGeneration
	}
	p, err := openOrder(key, id, m)
	if err != nil || p.State == "not-started" {
		return nil, OrderStatus{}, 0, ErrInvalid
	}
	action := "acme-order-located"
	switch {
	case acknowledge:
		if info != nil || url != "" || p.State != "dns-ready" || p.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") {
			return nil, OrderStatus{}, 0, ErrInvalid
		}
		p.State = "dns-acknowledged"
		action = "acme-dns-acknowledged"
	case info != nil:
		if url != "" || (p.State != "order-known" && p.State != "dns-ready" && p.State != "dns-acknowledged") || p.URL != info.URL || info.Expires <= time.Now().UTC().Format("2006-01-02T15:04:05Z") {
			return nil, OrderStatus{}, 0, ErrInvalid
		}
		p.State = "dns-ready"
		p.Expires = info.Expires
		p.Records = slices.Clone(info.Records)
		action = "acme-dns-prepared"
	default:
		if p.State != "request-pending" || url == "" {
			return nil, OrderStatus{}, 0, ErrInvalid
		}
		p.State = "order-known"
		p.URL = url
	}
	return sealOrder(key, id, m, p, action)
}

// WithStagingOrder lends the registered signer and exact sealed order scope to
// the locked connector callback. Neither URL nor signer is a public capability.
func WithStagingOrder(key, id, image []byte, expected uint64, use func(crypto.Signer, string, string, []string) error) error {
	m, _, err := decode(key, id, image)
	if err != nil {
		return err
	}
	if expected == 0 || expected != m.Generation {
		return ErrStaleGeneration
	}
	p, err := openOrder(key, id, m)
	if err != nil || p.State == "not-started" || use == nil {
		return ErrInvalid
	}
	account, err := openAccountPayload(key, id, m)
	if err != nil {
		return err
	}
	defer clear(account.PrivateKey)
	parsed, err := x509.ParsePKCS8PrivateKey(account.PrivateKey)
	if err != nil {
		return ErrInvalid
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return ErrInvalid
	}
	return use(signer, account.Registration.AccountURL, p.URL, slices.Clone(p.Domains))
}
