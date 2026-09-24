// Package fileinput provides bounded, path-safe reads for untrusted local files.
package fileinput

import (
	"errors"
	"io"
	"os"

	"github.com/denyfirst/rootwell/internal/limits"
)

var (
	// ErrEmpty means the selected input contains no bytes.
	ErrEmpty = errors.New("input is empty")
	// ErrTooLarge means the selected input exceeds the public size limit.
	ErrTooLarge = errors.New("input exceeds size limit")
	// ErrUnreadable means opening, reading, or closing the input failed.
	ErrUnreadable = errors.New("input could not be read")
)

// Read loads one bounded local input without exposing its path in returned
// errors. The caller must treat all returned bytes as untrusted.
func Read(path string) ([]byte, error) {
	return ReadAtMost(path, limits.MaxInputBytes)
}

// ReadAtMost loads one local input under a caller-selected positive limit.
// It preserves the same path-safe error contract as Read.
func ReadAtMost(path string, limit int64) ([]byte, error) {
	// The CLI intentionally lets its local operator select any readable file;
	// this is a read-only boundary, not a server-side path rooted in a sandbox.
	// #nosec G304 -- arbitrary local input selection is the command's contract.
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnreadable
	}

	contents, readErr := readLimited(file, limit)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		clear(contents)
		return nil, ErrUnreadable
	}
	return contents, nil
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	if reader == nil || limit < 1 {
		return nil, ErrUnreadable
	}

	limited := &io.LimitedReader{R: reader, N: limit + 1}
	contents, err := io.ReadAll(limited)
	if err != nil {
		clear(contents)
		return nil, ErrUnreadable
	}
	if int64(len(contents)) > limit {
		clear(contents)
		return nil, ErrTooLarge
	}
	if len(contents) == 0 {
		return nil, ErrEmpty
	}
	return contents, nil
}
