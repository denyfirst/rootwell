//go:build !linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNonLinuxOfflineCeremonyFailsClosed(t *testing.T) {
	for _, args := range [][]string{{"key-restore", "unused", "unused"}, {"setup-code", "unused", "unused"}, {"setup-code", "unused", "unused", "ada"}} {
		var output bytes.Buffer
		err := runOfflineCommand(args, func(string) (string, error) {
			t.Fatal("unsupported ceremony read a secret")
			return "", nil
		}, &output)
		if err == nil || !strings.Contains(err.Error(), "rootwelld keeps keys only on Linux") || output.Len() != 0 {
			t.Fatalf("%s off Linux: %v", args[0], err)
		}
	}
}

func TestNonLinuxInitCreatesNothing(t *testing.T) {
	root := t.TempDir()
	dir, keyFile := filepath.Join(root, "data"), filepath.Join(root, "keys", "instance.key")
	var output bytes.Buffer
	if err := initialize(dir, keyFile, strings.NewReader("SAVED\n"), &output); !errors.Is(err, errLinuxOnly) || output.Len() != 0 {
		t.Fatalf("init off Linux: %v", err)
	}
	for _, path := range []string{dir, keyFile} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("init off Linux created %s", path)
		}
	}
}
