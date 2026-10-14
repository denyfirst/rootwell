package inventorystore

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/cloudflareconfig"
	"github.com/denyfirst/rootwell/internal/inventoryseal"
)

var ErrDNSConfigInUse = errors.New("close the saved certificate request before changing DNS credentials")

// CloudflareStatus never contains the token, its digest or the provider zone ID.
// Saved means encrypted locally, not verified, authorized or connected.
type CloudflareStatus struct {
	State     string `json:"state"`
	ZoneName  string `json:"zone_name"`
	SavedAt   string `json:"saved_at"`
	CanChange bool   `json:"can_change"`
}

type cloudflarePayload struct {
	ZoneID   string `json:"zone_id"`
	ZoneName string `json:"zone_name"`
	Token    []byte `json:"token"`
	SavedAt  string `json:"saved_at"`
}

func cloudflareConfigID() []byte {
	sum := sha256.Sum256([]byte("rootwell.dns-cloudflare-config.v1"))
	return sum[:]
}
func cloudflareConfigKey(key, id []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, id, "rootwell.dns-cloudflare-config-key.v1", 32)
}

func openCloudflareConfig(key, id []byte, m manifest) (cloudflarePayload, error) {
	if len(m.CloudflareConfigs) == 0 {
		return cloudflarePayload{}, nil
	}
	if len(m.CloudflareConfigs) != 1 {
		return cloudflarePayload{}, ErrInvalid
	}
	item := m.CloudflareConfigs[0]
	if !bytes.Equal(item.ID, cloudflareConfigID()) || item.Generation < 2 || item.Generation > m.Generation || len(item.Ciphertext) > 2048 {
		return cloudflarePayload{}, ErrInvalid
	}
	k, err := cloudflareConfigKey(key, id)
	if err != nil {
		return cloudflarePayload{}, ErrInvalid
	}
	defer clear(k)
	plain, err := inventoryseal.Open(k, attachmentContext(id, item), item.Ciphertext)
	if err != nil {
		return cloudflarePayload{}, ErrInvalid
	}
	defer clear(plain)
	var p cloudflarePayload
	if !strictJSON(plain, &p) {
		clear(p.Token)
		return cloudflarePayload{}, ErrInvalid
	}
	at, timeErr := time.Parse(time.RFC3339, p.SavedAt)
	if timeErr != nil || at.Year() < 2020 || at.Year() > 2100 || at.UTC().Format("2006-01-02T15:04:05Z") != p.SavedAt || !cloudflareconfig.Valid(p.ZoneID, p.ZoneName, p.Token) {
		clear(p.Token)
		return cloudflarePayload{}, ErrInvalid
	}
	return p, nil
}

func cloudflarePublic(key, id []byte, m manifest) (CloudflareStatus, error) {
	p, err := openCloudflareConfig(key, id, m)
	if err != nil {
		return CloudflareStatus{}, err
	}
	defer clear(p.Token)
	order, err := openOrder(key, id, m)
	if err != nil {
		return CloudflareStatus{}, err
	}
	if len(p.Token) == 0 {
		return CloudflareStatus{State: "not-configured", CanChange: true}, nil
	}
	return CloudflareStatus{State: "saved", ZoneName: p.ZoneName, SavedAt: p.SavedAt, CanChange: order.State == "not-started"}, nil
}

func ReadCloudflareConfig(key, id, image []byte) (CloudflareStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return CloudflareStatus{}, 0, err
	}
	s, err := cloudflarePublic(key, id, m)
	if err != nil {
		return CloudflareStatus{}, 0, err
	}
	return s, m.Generation, nil
}

// ChangeCloudflareConfig returns a complete replacement image, never a token.
// nil token with empty zone fields explicitly removes the current credential.
// Rotation/removal refuses any active request, even an expired/completed one:
// explicit local closure is required. Initial save grants no network authority.
func ChangeCloudflareConfig(key, id, image []byte, expected uint64, zoneID, zoneName string, token []byte, remove bool) ([]byte, CloudflareStatus, uint64, error) {
	m, _, err := decode(key, id, image)
	if err != nil {
		return nil, CloudflareStatus{}, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, CloudflareStatus{}, 0, ErrStaleGeneration
	}
	if remove && (zoneID != "" || zoneName != "" || len(token) != 0 || len(m.CloudflareConfigs) == 0) || !remove && !cloudflareconfig.Valid(zoneID, zoneName, token) {
		return nil, CloudflareStatus{}, 0, ErrInvalid
	}
	s, err := cloudflarePublic(key, id, m)
	if err != nil {
		return nil, CloudflareStatus{}, 0, err
	}
	if !s.CanChange {
		return nil, CloudflareStatus{}, 0, ErrDNSConfigInUse
	}
	if m.Generation >= maxGeneration || len(m.History) >= maxHistory {
		return nil, CloudflareStatus{}, 0, ErrLimit
	}
	at := time.Now().UTC()
	if at.Year() < 2020 || at.Year() > 2100 || s.SavedAt != "" && at.Format("2006-01-02T15:04:05Z") < s.SavedAt {
		return nil, CloudflareStatus{}, 0, ErrInvalid
	}
	m.Generation++
	action := "dns-cloudflare-saved"
	eventZone := zoneName
	if remove {
		action, eventZone = "dns-cloudflare-removed", s.ZoneName
		m.CloudflareConfigs = nil
	} else {
		// Secret serialization is only an internal encryption boundary, not output.
		plain, err := json.Marshal(cloudflarePayload{ZoneID: zoneID, ZoneName: zoneName, Token: token, SavedAt: at.Format("2006-01-02T15:04:05Z")}) // #nosec G117 -- immediately AES-GCM sealed; never logged or returned
		if err != nil {
			return nil, CloudflareStatus{}, 0, ErrInvalid
		}
		defer clear(plain)
		k, err := cloudflareConfigKey(key, id)
		if err != nil {
			return nil, CloudflareStatus{}, 0, ErrInvalid
		}
		defer clear(k)
		item := sealedRecord{ID: cloudflareConfigID(), Generation: m.Generation}
		item.Ciphertext, err = inventoryseal.Seal(k, attachmentContext(id, item), plain)
		if err != nil {
			return nil, CloudflareStatus{}, 0, ErrInvalid
		}
		m.CloudflareConfigs = []sealedRecord{item}
	}
	// Public zone identity, not a credential digest or raw provider identifier.
	sum := sha256.Sum256([]byte("rootwell.dns-zone-history.v1:" + eventZone))
	hexID := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 32)
	for i := range parts {
		parts[i] = hexID[i*2 : i*2+2]
	}
	if err := addEvent(key, &m, action, []string{strings.Join(parts, ":")}); err != nil {
		return nil, CloudflareStatus{}, 0, err
	}
	next, err := encode(key, m)
	if err != nil {
		return nil, CloudflareStatus{}, 0, err
	}
	status, generation, err := ReadCloudflareConfig(key, id, next)
	if err != nil {
		return nil, CloudflareStatus{}, 0, err
	}
	return next, status, generation, nil
}
