//go:build !linux

package secretfile

func WriteNew(string, []byte) error { return ErrUnsupported }

func Preflight(string) error { return ErrUnsupported }
