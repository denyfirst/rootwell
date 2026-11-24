// Command rootwelld serves Rootwell's pages on this host's loopback addresses
// and keeps its accounts and certificates in the vault.
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/denyfirst/rootwell/internal/accountstore"
	"github.com/denyfirst/rootwell/internal/vault"
	"golang.org/x/term"
)

const localHost = "localhost:4180"

const usage = "usage: rootwelld init <private-data-dir> <instance-key-file> | rootwelld serve <private-data-dir> <instance-key-file> <workbench-assets-dir> | rootwelld setup-code <private-data-dir> <instance-key-file> [account-name] | rootwelld key-restore <private-data-dir> <instance-key-file>"

var errLinuxOnly = errors.New("rootwelld keeps keys only on Linux; run it there, or in its container")

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if err := hardenProcess(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if isOfflineCommand(args) {
		if !terminal(os.Stdin) || !terminal(os.Stdout) {
			fmt.Fprintln(os.Stderr, "this command needs an interactive local terminal; no secret was read or shown")
			return 2
		}
		if err := runOfflineCommand(args, readTerminalSecret, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) == 3 && args[0] == "init" {
		if !terminal(os.Stdin) || !terminal(os.Stdout) {
			fmt.Fprintln(os.Stderr, "init needs an interactive local terminal; nothing was created")
			return 2
		}
		if err := initialize(args[1], args[2], os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if len(args) == 4 && args[0] == "serve" {
		if err := serve(args[1], args[2], args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, usage)
	return 2
}

func terminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// keyOutsideData refuses an instance key file inside the data directory: a
// copy of the data must never carry the key that opens it.
func keyOutsideData(dir, keyFile string) error {
	data, dataErr := filepath.Abs(dir)
	key, keyErr := filepath.Abs(keyFile)
	if dataErr != nil || keyErr != nil {
		return errors.New("the data directory and the key file need clear paths")
	}
	rel, err := filepath.Rel(data, key)
	if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("keep the instance key file outside the data directory, so a copy of the data never carries its key")
	}
	return nil
}

// custody says whether this host can keep keys. Only Linux has the
// private-file checks the vault relies on.
func custody() bool { return runtime.GOOS == "linux" }

func privateDirectory(dir string) error {
	// #nosec G703 -- dir is a local operator CLI path, never an HTTP input.
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("the data directory must be private to its owner (0700)")
	}
	return nil
}

// initialize makes the instance key and the vault, and prints a setup code
// for the first account. The key's recovery code is shown once and must be
// confirmed as saved before anything is written.
func initialize(dir, keyFile string, input io.Reader, output io.Writer) error {
	if !custody() {
		return errLinuxOnly
	}
	if dir == "" || keyFile == "" {
		return errors.New("a private data directory and an instance key file are required")
	}
	if err := keyOutsideData(dir, keyFile); err != nil {
		return err
	}
	// #nosec G703 -- dir is a local operator CLI path, never an HTTP input.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("the data directory could not be created")
	}
	if err := privateDirectory(dir); err != nil {
		return err
	}
	// #nosec G703 -- keyFile is a local operator CLI path, never an HTTP input.
	if _, err := os.Lstat(keyFile); !os.IsNotExist(err) {
		return errors.New("an instance key file already exists there; Rootwell never replaces one")
	}
	// #nosec G703 -- the path is derived from the local operator CLI path.
	if _, err := os.Lstat(filepath.Join(dir, "rootwell.db")); !os.IsNotExist(err) {
		return errors.New("this data directory holds an installation already; for a new setup code, use rootwelld setup-code")
	}
	key, err := vault.NewInstanceKey()
	if err != nil {
		return errors.New("an instance key could not be made")
	}
	defer clear(key)
	recovery, err := vault.RecoveryCode(key)
	if err != nil {
		return errors.New("an instance key could not be made")
	}
	message := fmt.Sprintf("Instance key recovery code (shown only here). It rebuilds the key file %s if that file is lost; without both, every saved certificate and key is lost. Keep it apart from this host and from backups:\n\n  %s\n\nType SAVED and press Enter once it is written down: ", keyFile, recovery)
	if _, err := io.WriteString(output, message); err != nil {
		return errors.New("the recovery code could not be shown; nothing was created")
	}
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "SAVED" {
		return errors.New("nothing was created, because saving the recovery code was not confirmed")
	}
	if err := vault.WriteKeyFile(keyFile, key); err != nil {
		return errors.New("the instance key file could not be written; its directory must be private (0700) and owned by this user")
	}
	v, err := vault.Create(dir, key)
	if err != nil {
		return errors.New("the vault could not be created in the data directory; remove the new key file before trying again")
	}
	code, until, err := accountstore.New(v, time.Now).NewSetupCode("")
	if closeErr := v.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("the installation was created, but its setup code was not saved; make one with rootwelld setup-code")
	}
	if _, err := io.WriteString(output, "\nInstallation created.\n\n"); err != nil {
		return errors.New("the installation was created, but its setup code could not be shown; make one with rootwelld setup-code")
	}
	return showSetupCode(output, code, until, "")
}

// showSetupCode prints a setup code and what to do with it.
func showSetupCode(out io.Writer, code string, until time.Time, name string) error {
	with := "the name and the password you want"
	if name != "" {
		with = "the name " + name + " and the new password you want; this replaces its password and phone"
	}
	_, err := fmt.Fprintf(out, "Setup code (works once, until %s UTC):\n\n  %s\n\nWith rootwelld running, open its setup page, /setup, and enter this code with %s. If the time runs out, make a new code with rootwelld setup-code.\n",
		until.UTC().Format("2006-01-02 15:04"), code, with)
	if err != nil {
		return errors.New("the setup code could not be shown; make a new one with rootwelld setup-code")
	}
	return nil
}

func serve(dir, keyFile, assetsDir string) error {
	if !custody() {
		return errLinuxOnly
	}
	if err := privateDirectory(dir); err != nil {
		return err
	}
	if err := keyOutsideData(dir, keyFile); err != nil {
		return err
	}
	key, err := vault.ReadKeyFile(keyFile)
	if err != nil {
		return errors.New("the instance key file could not be read; it must be a private 0600 file of this user")
	}
	v, err := vault.Open(dir, key)
	clear(key)
	if err != nil {
		return errors.New("the vault did not open with this instance key, or another rootwelld holds it")
	}
	defer v.Close()
	gate, err := newGate(v, assetsDir, localHost)
	if err != nil {
		return err
	}
	defer gate.Close()
	server := &http.Server{
		Handler:           gate,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 8192,
	}
	listeners, err := listenLoopback(4180)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "Rootwell is available at http://localhost:4180 (this host only)")
	if exists, err := gate.accounts.Exists(); err == nil && !exists {
		fmt.Fprintln(os.Stdout, "No account yet: open http://localhost:4180/setup with the setup code from rootwelld init, or a new one from rootwelld setup-code.")
	}
	served := make(chan error, len(listeners))
	for _, listener := range listeners {
		go func() { served <- server.Serve(listener) }()
	}
	err = <-served
	_ = server.Close()
	return err
}

// listenLoopback opens the port on both loopback addresses. Browsers often try
// [::1] first for localhost, so leaving it free would let another local account
// serve this origin and collect the password (audit RW-03). A host without IPv6
// keeps IPv4 alone; a taken IPv6 port refuses the start.
func listenLoopback(port int) ([]net.Listener, error) {
	v4, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, errors.New("loopback listener could not be opened")
	}
	v6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err == nil {
		return []net.Listener{v4, v6}, nil
	}
	if errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) {
		return []net.Listener{v4}, nil
	}
	_ = v4.Close()
	return nil, errors.New("the IPv6 loopback port could not be opened; if another program holds it, stop that program, because Rootwell will not share its address")
}
