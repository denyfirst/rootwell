package inventorystore

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/denyfirst/rootwell/internal/inventoryseal"
	"github.com/denyfirst/rootwell/internal/providerretry"
	"github.com/denyfirst/rootwell/internal/publicinventory"
)

// Provider-wide wait is independent of certificate deletion. It cannot be
// evaded by selecting/deleting a different timing entry. No credential/URI.
type stagingWait struct {
	Account    string `json:"account"`
	ObservedAt string `json:"observed_at"`
	NotBefore  string `json:"not_before"`
	Blocked    bool   `json:"blocked"`
}

type StagingProviderWaitStatus struct {
	ObservedAt string `json:"observed_at"`
	NotBefore  string `json:"not_before"`
	Blocked    bool   `json:"blocked"`
	Ready      bool   `json:"ready"`
}

func ReadStagingProviderWait(key, id, image []byte) (StagingProviderWaitStatus, uint64, error) {
	return readStagingWaitAt(key, id, image, time.Now().UTC())
}
func readStagingWaitAt(key, id, image []byte, at time.Time) (StagingProviderWaitStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return StagingProviderWaitStatus{}, 0, err
	}
	p, err := openStagingWait(key, id, m)
	if err != nil || !timingClock(key, id, m, at, nil) {
		return StagingProviderWaitStatus{}, 0, ErrInvalid
	}
	return StagingProviderWaitStatus{ObservedAt: p.ObservedAt, NotBefore: p.NotBefore, Blocked: p.Blocked, Ready: stagingWaitReady(p, at)}, m.Generation, nil
}

func stagingWaitID() []byte {
	sum := sha256.Sum256([]byte("rootwell.acme-staging-provider-wait.v1"))
	return sum[:]
}
func stagingWaitKey(key, id []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, id, "rootwell.acme-staging-provider-wait-key.v1", 32)
}

func openStagingWait(key, id []byte, m manifest) (stagingWait, error) {
	bad := func() (stagingWait, error) { return stagingWait{}, ErrInvalid }
	if len(m.StagingProviderWait) == 0 {
		return stagingWait{}, nil
	}
	if len(m.StagingProviderWait) != 1 {
		return bad()
	}
	item := m.StagingProviderWait[0]
	if !bytes.Equal(item.ID, stagingWaitID()) || item.Generation < 2 || item.Generation > m.Generation || len(item.Ciphertext) > 512 {
		return bad()
	}
	k, err := stagingWaitKey(key, id)
	if err != nil {
		return bad()
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	defer clear(plain)
	var p stagingWait
	if err != nil || !strictJSON(plain, &p) || !publicinventory.ValidFingerprint(p.Account) {
		return bad()
	}
	seen, ok := timingTime(p.ObservedAt)
	if !ok {
		return bad()
	}
	if p.NotBefore != "" {
		next, ok := timingTime(p.NotBefore)
		if !ok || !next.After(seen) || next.Sub(seen) > providerretry.MaxProviderWait {
			return bad()
		}
	}
	if !p.Blocked && p.NotBefore == "" {
		return bad()
	}
	account, err := accountStatus(key, id, m)
	if err != nil || account.Registration != "registered" || account.Fingerprint != p.Account {
		return bad()
	}
	prepared, err := time.Parse(time.RFC3339, account.PreparedAt)
	if err != nil || seen.Before(prepared) {
		return bad()
	}
	return p, nil
}

func constrainStagingWait(key, id []byte, m *manifest, hint providerretry.Hint, at time.Time) error {
	if hint.NotBefore.IsZero() && !hint.Blocked {
		return nil
	}
	prior, err := openStagingWait(key, id, *m)
	if err != nil {
		return err
	}
	if prior.ObservedAt != "" {
		seen, _ := timingTime(prior.ObservedAt)
		if at.Before(seen) {
			return ErrInvalid
		}
	}
	account, err := accountStatus(key, id, *m)
	if err != nil || account.Registration != "registered" {
		return ErrInvalid
	}
	next := hint.NotBefore.UTC()
	_, valid := timingTime(timingStamp(next))
	blocked := prior.Blocked || hint.Blocked || !next.IsZero() && (!valid || next.Sub(at) > providerretry.MaxProviderWait)
	if !blocked && !next.After(at) {
		return nil
	}
	p := stagingWait{Account: account.Fingerprint, ObservedAt: timingStamp(at), Blocked: blocked}
	if next.After(at) && valid && next.Sub(at) <= providerretry.MaxProviderWait {
		p.NotBefore = timingStamp(next)
	}
	if prior.NotBefore != "" {
		old, _ := timingTime(prior.NotBefore)
		if old.After(at) && (p.NotBefore == "" || old.After(next)) {
			p.NotBefore = prior.NotBefore
		}
	}
	plain, err := json.Marshal(p)
	if err != nil || len(plain) > 448 {
		return ErrLimit
	}
	defer clear(plain)
	k, err := stagingWaitKey(key, id)
	if err != nil {
		return err
	}
	defer clear(k)
	item := sealedRecord{ID: stagingWaitID(), Generation: m.Generation}
	item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
	if err != nil {
		return err
	}
	m.StagingProviderWait = []sealedRecord{item}
	return nil
}

func stagingWaitReady(p stagingWait, at time.Time) bool {
	if p.ObservedAt == "" {
		return true
	}
	seen, ok := timingTime(p.ObservedAt)
	if !ok || at.Before(seen) || p.Blocked {
		return false
	}
	if p.NotBefore != "" {
		next, ok := timingTime(p.NotBefore)
		if !ok || at.Before(next) {
			return false
		}
	}
	return true
}
