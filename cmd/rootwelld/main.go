// Command rootwelld provides an operator-initialized, loopback-only Workbench.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/denyfirst/rootwell/internal/instanceaccess"
)

const localHost = "localhost:4180"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 2 && args[0] == "init" {
		if !terminal(os.Stdin) || !terminal(os.Stdout) {
			fmt.Fprintln(os.Stderr, "init requires an interactive local terminal; no password was printed")
			return 2
		}
		if err := initialize(args[1], os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) == 3 && args[0] == "serve" {
		if err := serve(args[1], args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: rootwelld init <private-data-dir> | rootwelld serve <private-data-dir> <workbench-assets-dir>")
	return 2
}

func terminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func initialize(dir string, input io.Reader, output io.Writer) error {
	if dir == "" {
		return errors.New("a private data directory is required")
	}
	// #nosec G703 -- dir is a local operator CLI path, never an HTTP input.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("private data directory could not be created")
	}
	// #nosec G703 -- dir is a local operator CLI path, never an HTTP input.
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return errors.New("data directory must be private to its owner")
	}
	accessPath := filepath.Join(dir, "access.json")
	// #nosec G703 -- accessPath is derived from the local operator CLI path.
	if _, err := os.Lstat(accessPath); err == nil {
		return errors.New("installation already exists; its password cannot be redisplayed")
	} else if !os.IsNotExist(err) {
		return errors.New("installation access file could not be checked")
	}
	password, err := instanceaccess.GenerateInitialPassword()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(output, "Rootwell setup password (shown only here; save it now):\n\n  %s\n\nType SAVED and press Enter to activate it: ", password); err != nil {
		return errors.New("initial password could not be shown; installation was not created")
	}
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "SAVED" {
		return errors.New("installation was not created because saving the password was not confirmed")
	}
	if err := instanceaccess.Create(accessPath, password); err != nil {
		return err
	}
	if _, err := io.WriteString(output, "\nInstallation created. Sign in on localhost and change this password before using Workbench.\n"); err != nil {
		return errors.New("installation was created, but the final confirmation could not be shown")
	}
	return nil
}

func serve(dir, assetsDir string) error {
	// #nosec G703 -- dir is a local operator CLI path, never an HTTP input.
	directory, err := os.Stat(dir)
	if err != nil || !directory.IsDir() || (runtime.GOOS != "windows" && directory.Mode().Perm()&0o077 != 0) {
		return errors.New("installation data directory must be private to its owner")
	}
	accessPath := filepath.Join(dir, "access.json")
	// #nosec G703 -- accessPath is derived from the local operator CLI path.
	accessInfo, err := os.Lstat(accessPath)
	if err != nil {
		return errors.New("installation is not initialized; run rootwelld init locally first")
	}
	if !accessInfo.Mode().IsRegular() || (runtime.GOOS != "windows" && accessInfo.Mode().Perm()&0o077 != 0) {
		return errors.New("installation access file must be private and regular")
	}
	gate, err := newGate(accessPath, assetsDir, localHost)
	if err != nil {
		return err
	}
	defer gate.Close()
	server := &http.Server{
		Addr: "127.0.0.1:4180", Handler: gate,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 8192,
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:4180")
	if err != nil {
		return errors.New("loopback listener could not be opened")
	}
	defer listener.Close()
	fmt.Fprintln(os.Stdout, "Rootwell is available at http://localhost:4180 (this host only)")
	return server.Serve(listener)
}
