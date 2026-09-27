//go:build !linux

package instanceaccess

// Recovery enrollment and reset require the reviewed Linux writer protocol.
func EnrollRecovery(_ string, _ string) (string, error) { return "", ErrRecoveryUnsupported }
func RotateRecovery(_ string, _ string) (string, error) { return "", ErrRecoveryUnsupported }
func RecoverPassword(_ string, _, _ string) (string, error) {
	return "", ErrRecoveryUnsupported
}
