//go:build !linux

package vault

// Secret custody runs on Linux only. Elsewhere the checked paths refuse; the
// package's own tests reach the store through the unchecked test opener.
func privateDirectory(string, string) error { return ErrRefused }
func privateKeyFile(string) error           { return ErrRefused }
func syncDirectory(string) error            { return ErrRefused }
