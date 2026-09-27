//go:build !linux

package instanceaccess

// CommitIdentityUpgrade refuses to mutate access on platforms without the
// reviewed Linux lock, atomic replacement, and directory-sync boundary.
func CommitIdentityUpgrade(_ string, _ string, _ IdentityUpgradeCandidate) error {
	return ErrUpgradeUnsupported
}
