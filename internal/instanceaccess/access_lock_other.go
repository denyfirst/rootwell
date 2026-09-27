//go:build !linux

package instanceaccess

// Non-Linux password changes retain the existing development behavior.
// Durable storage and identity installation are not enabled on these systems.
func withAccessWriteLock(_ string, fn func() error) error { return fn() }

func syncAccessDirectory(_ string) error { return nil }
