package instanceaccess

import (
	"bytes"
	"crypto/hmac"
)

type recoveryAction uint8

const (
	recoveryEnroll recoveryAction = iota
	recoveryRotate
	recoveryResetPassword
)

// changeRecoveryLocked performs an offline recovery ceremony under the same
// private Linux writer lock used for password changes. A returned code is safe
// to display only after the replacement has been durably verified.
func changeRecoveryLocked(path, credential, nextPassword string, action recoveryAction,
	replaceFile func(string, []byte) error, syncDir func(string) error) (string, error) {
	if action == recoveryResetPassword {
		if err := checkPassword(nextPassword); err != nil {
			return "", err
		}
	}
	current, err := readAccess(path)
	if err != nil {
		return "", err
	}
	e, err := parseEnvelope(current)
	if err != nil {
		return "", err
	}
	var key []byte
	if action != recoveryResetPassword {
		// Do not disclose enrollment, version, or setup state to a caller
		// who has not authenticated with the current password.
		key, _, _, err = unsealBody(current, credential)
		if err != nil {
			return "", err
		}
		defer clear(key)
		nextPassword = credential
	}
	if e.State != ready {
		return "", ErrChangeRequired
	}
	if e.Version == 1 {
		return "", ErrIdentityMissing
	}
	if action == recoveryEnroll && e.Version == 3 {
		return "", ErrRecoveryExists
	}
	if action != recoveryEnroll && e.Version != 3 {
		return "", ErrRecoveryMissing
	}
	if action == recoveryResetPassword {
		key, err = OpenRecoveryWrap(e.RecoveryWrap, credential, e.InstallationID)
		if err != nil || !hmac.Equal(recoveryCheck(key, e.InstallationID, e.RecoveryWrap), e.RecoveryCheck) {
			clear(key)
			return "", ErrInvalidRecovery
		}
		defer clear(key)
	}
	wrap, code, err := CreateRecoveryWrap(e.InstallationID, key)
	if err != nil {
		return "", err
	}
	check, err := OpenRecoveryWrap(wrap, code, e.InstallationID)
	if err != nil || !bytes.Equal(check, key) {
		clear(check)
		return "", ErrInvalidRecovery
	}
	clear(check)
	newBody, err := sealWithRecovery(key, nextPassword, ready, e.InstallationID, wrap)
	if err != nil {
		return "", err
	}
	if err := replaceFile(path, newBody); err != nil {
		return "", err
	}
	if err := syncDir(path); err != nil {
		return "", ErrWriteUncertain
	}
	installed, err := readAccess(path)
	if err != nil || !bytes.Equal(installed, newBody) {
		return "", ErrWriteUncertain
	}
	return code, nil
}
