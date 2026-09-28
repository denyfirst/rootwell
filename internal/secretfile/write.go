// Package secretfile writes a new secret file only on platforms with a
// reviewed private-directory and no-overwrite contract.
package secretfile

import "errors"

var (
	ErrUnsafe      = errors.New("secret output is unsafe")
	ErrUncertain   = errors.New("secret output may have been created")
	ErrUnsupported = errors.New("secret output is unsupported on this platform")
)
