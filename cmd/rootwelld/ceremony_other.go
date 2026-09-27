//go:build !linux

package main

import (
	"errors"
	"io"
)

func runOfflineCommand(_ []string, _ secretReader, _ io.Writer) error {
	return errors.New("offline recovery commands require the reviewed Linux storage writer")
}
