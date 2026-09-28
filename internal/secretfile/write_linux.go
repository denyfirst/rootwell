//go:build linux

package secretfile

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Preflight refuses unsupported destinations before secret input is read. It
// is advisory; WriteNew independently rechecks all conditions before writing.
func Preflight(path string) error {
	if path == "" || filepath.Base(path) == "." {
		return unsafe("invalid destination")
	}
	dir := filepath.Dir(path)
	listed, err := os.Lstat(dir)
	if err != nil || !listed.IsDir() || listed.Mode().Perm()&0o077 != 0 {
		return unsafe("directory permissions")
	}
	owner, ok := listed.Sys().(*syscall.Stat_t)
	if !ok || int64(owner.Uid) != int64(os.Geteuid()) {
		return unsafe("directory ownership")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return unsafe("destination exists")
	}
	return nil
}

// WriteNew requires an existing owner-private directory and never replaces an
// existing output. An unexpected failure after link may leave a valid output;
// callers receive ErrUncertain and must inspect the named destination.
func WriteNew(path string, data []byte) error {
	if path == "" || len(data) == 0 || filepath.Base(path) == "." {
		return unsafe("invalid destination or empty data")
	}
	dir := filepath.Dir(path)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return unsafe("open root")
	}
	defer root.Close()
	listed, err := os.Lstat(dir)
	if err != nil || !listed.IsDir() || listed.Mode().Perm()&0o077 != 0 {
		return unsafe("directory permissions")
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(listed, opened) {
		return unsafe("directory identity")
	}
	owner, ok := listed.Sys().(*syscall.Stat_t)
	if !ok || int64(owner.Uid) != int64(os.Geteuid()) {
		return unsafe("directory ownership")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return unsafe("random staging name")
	}
	stagingName := ".rootwell-secret-" + hex.EncodeToString(nonce[:])
	staging, err := root.OpenFile(stagingName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return unsafe("create staging file")
	}
	defer func() { _ = root.Remove(stagingName) }()
	stagedInfo, err := staging.Stat()
	if err != nil || !stagedInfo.Mode().IsRegular() || stagedInfo.Mode().Perm()&0o077 != 0 {
		_ = staging.Close()
		return unsafe("staging permissions")
	}
	if written, err := staging.Write(data); err != nil || written != len(data) {
		_ = staging.Close()
		return unsafe("write staging file")
	}
	if err := staging.Sync(); err != nil {
		_ = staging.Close()
		return unsafe("sync staging file")
	}
	if _, err := staging.Seek(0, io.SeekStart); err != nil {
		_ = staging.Close()
		return unsafe("seek staging file")
	}
	readback := make([]byte, len(data))
	defer clear(readback)
	if _, err := io.ReadFull(staging, readback); err != nil || !bytes.Equal(readback, data) {
		_ = staging.Close()
		return unsafe("verify staging file")
	}
	if err := staging.Close(); err != nil {
		return unsafe("close staging file")
	}
	name := filepath.Base(path)
	if err := root.Link(stagingName, name); err != nil {
		return unsafe("link destination")
	}
	outputInfo, err := root.Lstat(name)
	if err != nil || !os.SameFile(stagedInfo, outputInfo) {
		return ErrUncertain
	}
	if err := root.Remove(stagingName); err != nil {
		return ErrUncertain
	}
	directory, err := root.Open(".")
	if err != nil {
		return ErrUncertain
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrUncertain
	}
	return nil
}

func unsafe(stage string) error {
	return fmt.Errorf("%w: %s", ErrUnsafe, stage)
}
