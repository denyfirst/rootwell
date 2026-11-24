//go:build !linux

package main

import (
	"errors"
	"io"
)

func runOfflineCommand(_ []string, _ secretReader, _ io.Writer) error {
	return errors.New("rootwelld keeps keys only on Linux; run it there, or in its container")
}
