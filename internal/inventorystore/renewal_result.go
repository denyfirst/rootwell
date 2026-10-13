package inventorystore

import "github.com/denyfirst/rootwell/internal/publicinventory"

// RenewalResult describes two currently saved public certificates, not current
// trust, revocation, deployment or authority to replace the original pair.
type RenewalResult struct {
	OriginalFingerprint string `json:"original_fingerprint"`
	NewFingerprint      string `json:"new_fingerprint"`
	OriginalExpiry      string `json:"original_expiry"`
	NewExpiry           string `json:"new_expiry"`
	ExpiryExtended      bool   `json:"expiry_extended"`
}

// ReadStagingRenewalResult authenticates the complete image before deriving a
// public summary. Nil means no live completed renewal in the active scope;
// ordinary issuance, pending, deleted and locally closed requests have no result.
// Nothing is written, fetched, copied from a private material or newly trusted.
func ReadStagingRenewalResult(key, id, image []byte, expected uint64) (*RenewalResult, uint64, error) {
	m, records, err := decode(key, id, image)
	if err != nil {
		return nil, 0, err
	}
	if expected == 0 || expected != m.Generation {
		return nil, 0, ErrStaleGeneration
	}
	order, err := openOrder(key, id, m)
	if err != nil {
		return nil, 0, err
	}
	issuance, err := openIssuance(key, id, m)
	if err != nil {
		return nil, 0, err
	}
	if order.RenewalSource == "" || issuance.Completion == nil || issuance.Completion.DeletedAt != "" {
		return nil, m.Generation, nil
	}
	var original, renewed []byte
	for _, record := range records {
		if record.Fingerprint == order.RenewalSource {
			original = record.DER
		}
		if record.Fingerprint == issuance.Completion.Fingerprint {
			renewed = record.DER
		}
	}
	comparison, err := publicinventory.Compare(original, renewed)
	if err != nil || comparison.OldFingerprint != order.RenewalSource || comparison.NewFingerprint != issuance.Completion.Fingerprint || comparison.SameCertificate || comparison.SamePublicKey || len(comparison.AddedNames) != 0 || len(comparison.RemovedNames) != 0 {
		return nil, 0, ErrInvalid
	}
	return &RenewalResult{OriginalFingerprint: comparison.OldFingerprint, NewFingerprint: comparison.NewFingerprint, OriginalExpiry: comparison.OldExpiry, NewExpiry: comparison.NewExpiry, ExpiryExtended: comparison.ExpiryExtended}, m.Generation, nil
}
