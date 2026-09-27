//go:build linux

package instanceaccess

// CommitIdentityUpgrade installs a previously prepared v2 candidate on Linux.
// It is intended for a private local filesystem; network mounts are not
// detected or approved. This is a core operation, not a CLI or web action,
// and must not be used as a recovery or backup ceremony.
func CommitIdentityUpgrade(path, password string, candidate IdentityUpgradeCandidate) error {
	if len(password) == 0 || len(password) > maxPass {
		return ErrWrongPassword
	}
	if candidate.ExpectedRevision == [32]byte{} || len(candidate.InstallationID) != 16 ||
		len(candidate.EncryptedAccess) == 0 || len(candidate.EncryptedAccess) > maxFile {
		return ErrInvalidUpgrade
	}
	return withAccessWriteLock(path, func() error {
		return commitIdentityUpgradeLocked(path, password, candidate, replace, syncAccessDirectory)
	})
}
