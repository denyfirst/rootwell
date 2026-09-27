//go:build linux

package instanceaccess

// EnrollRecovery adds an offline code to an authenticated ready v2 instance.
// The code must be displayed once on a trusted local terminal and kept apart
// from any backup. This is an internal core, not a browser or CLI action.
func EnrollRecovery(path, password string) (string, error) {
	return changeRecovery(path, password, "", recoveryEnroll)
}

// RotateRecovery invalidates the current code for the active access file.
// Older backups remain decryptable with their old code until destroyed.
func RotateRecovery(path, password string) (string, error) {
	return changeRecovery(path, password, "", recoveryRotate)
}

// RecoverPassword uses an enrolled code to set a new login password and rotates
// the recovery code in the same access-file replacement. It does not restore
// inventory records or revoke copies of old backups.
func RecoverPassword(path, code, nextPassword string) (string, error) {
	return changeRecovery(path, code, nextPassword, recoveryResetPassword)
}

func changeRecovery(path, credential, nextPassword string, action recoveryAction) (string, error) {
	if len(credential) == 0 || len(credential) > maxPass {
		return "", ErrInvalidRecoveryInput
	}
	var code string
	err := withAccessWriteLock(path, func() error {
		var err error
		code, err = changeRecoveryLocked(path, credential, nextPassword, action, replace, syncAccessDirectory)
		return err
	})
	if err != nil {
		return "", err
	}
	return code, nil
}
