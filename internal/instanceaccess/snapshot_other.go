//go:build !linux

package instanceaccess

func ExportAccessSnapshot(_, _, _, _ string) error { return ErrSnapshotUnsupported }
func VerifyAccessSnapshot(_ string, _ string, _ SnapshotUnlock) ([]byte, error) {
	return nil, ErrSnapshotUnsupported
}
func RestoreAccessSnapshot(_, _, _ string, _ SnapshotUnlock) error {
	return ErrSnapshotUnsupported
}
