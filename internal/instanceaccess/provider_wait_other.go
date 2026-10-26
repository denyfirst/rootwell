//go:build !linux

package instanceaccess

func RunStagingProviderRead(string, []byte, []byte, [32]byte, func() bool, func(func() bool) error) error {
	return ErrRecoveryUnsupported
}
