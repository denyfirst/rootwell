//go:build !linux

package instanceaccess

// Native non-Linux rootwelld remains development-only and has no approved
// offline recovery writer. This no-op retains its existing serve behavior.
func AcquireOperationLock(_ string) (func(), error) { return func() {}, nil }
