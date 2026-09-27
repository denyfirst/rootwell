package instanceaccess

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
)

// commitIdentityUpgradeLocked is separated from the Linux lock acquisition
// so validation and fault ordering can be tested on every development OS.
// Only the Linux CommitIdentityUpgrade wrapper may call it in production.
func commitIdentityUpgradeLocked(path, password string, candidate IdentityUpgradeCandidate,
	replaceFile func(string, []byte) error, syncDir func(string) error) error {
	current, err := readAccess(path)
	if err != nil {
		return err
	}
	if sha256.Sum256(current) != candidate.ExpectedRevision {
		return ErrStaleUpgrade
	}
	oldKey, state, oldID, err := unsealBody(current, password)
	if err != nil {
		return err
	}
	defer clear(oldKey)
	if state != ready {
		return ErrChangeRequired
	}
	if len(oldID) != 0 {
		return ErrIdentityExists
	}
	newKey, newState, newID, err := unsealBody(candidate.EncryptedAccess, password)
	if err != nil {
		return ErrInvalidUpgrade
	}
	defer clear(newKey)
	if newState != ready || len(newID) != 16 || !bytes.Equal(newID, candidate.InstallationID) ||
		subtle.ConstantTimeCompare(oldKey, newKey) != 1 {
		return ErrInvalidUpgrade
	}
	if err := replaceFile(path, candidate.EncryptedAccess); err != nil {
		return err
	}
	if err := syncDir(path); err != nil {
		return ErrWriteUncertain
	}
	installed, err := readAccess(path)
	if err != nil || !bytes.Equal(installed, candidate.EncryptedAccess) {
		return ErrWriteUncertain
	}
	return nil
}
