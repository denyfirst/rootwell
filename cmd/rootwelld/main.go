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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/denyfirst/rootwell/internal/certstore"
	"github.com/denyfirst/rootwell/internal/instanceaccess"
	"github.com/denyfirst/rootwell/internal/vault"
	"golang.org/x/term"
)

const localHost = "localhost:4180"

const usage = "usage: rootwelld init <private-data-dir> <instance-key-file> | rootwelld serve <private-data-dir> <instance-key-file> <workbench-assets-dir> | rootwelld key-restore <private-data-dir> <instance-key-file> | rootwelld recovery-enroll|recovery-rotate|recovery-reset <private-data-dir> | rootwelld access-snapshot <private-data-dir> <new-snapshot-file> | rootwelld access-verify <snapshot-file> password|code | rootwelld access-restore <snapshot-file> <fresh-private-data-dir> password|code"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if err := hardenProcess(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if isOfflineCommand(args) {
		if !terminal(os.Stdin) || !terminal(os.Stdout) {
			fmt.Fprintln(os.Stderr, "offline recovery commands require an interactive local terminal; no secret was read")
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
			fmt.Fprintln(os.Stderr, "init requires an interactive local terminal; no password was printed")
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

// custody says whether this host keeps certificates. Only Linux has the
// private-file checks the vault relies on; elsewhere the pages open as a
// preview and saving is turned off.
func custody() bool { return runtime.GOOS == "linux" }

func initialize(dir, keyFile string, input io.Reader, output io.Writer) error {
	if dir == "" || keyFile == "" {
		return errors.New("a private data directory and an instance key file are required")
	}
	if err := keyOutsideData(dir, keyFile); err != nil {
		return err
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
	if custody() {
		// #nosec G703 -- keyFile is a local operator CLI path, never an HTTP input.
		if _, err := os.Lstat(keyFile); !os.IsNotExist(err) {
			return errors.New("an instance key file already exists there; Rootwell never replaces one")
		}
	}
	password, err := instanceaccess.GenerateInitialPassword()
	if err != nil {
		return err
	}
	var key []byte
	var code string
	if custody() {
		if key, err = vault.NewInstanceKey(); err != nil {
			return errors.New("an instance key could not be made")
		}
		defer clear(key)
		if code, err = vault.RecoveryCode(key); err != nil {
			return errors.New("an instance key could not be made")
		}
	}
	message := fmt.Sprintf("Rootwell setup password (shown only here; save it now):\n\n  %s\n\n", password)
	if custody() {
		message += fmt.Sprintf("Instance key recovery code (shown only here). It rebuilds the key file %s if that file is lost; without both, every saved certificate and key is lost. Keep it apart from this host and from backups:\n\n  %s\n\n", keyFile, code)
	}
	if _, err := io.WriteString(output, message+"Type SAVED and press Enter to activate them: "); err != nil {
		return errors.New("the setup secrets could not be shown; installation was not created")
	}
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "SAVED" {
		return errors.New("installation was not created because saving the secrets was not confirmed")
	}
	if custody() {
		// The key comes first and access last: an installation exists only once
		// its access file does, so a failed start leaves nothing that serves.
		if err := vault.WriteKeyFile(keyFile, key); err != nil {
			return errors.New("the instance key file could not be written; its directory must be private (0700) and owned by this user")
		}
		v, err := vault.Create(dir, key)
		if err != nil {
			return errors.New("the certificate vault could not be created in the data directory; remove the new key file before trying again")
		}
		if err := v.Close(); err != nil {
			return errors.New("the certificate vault could not be closed cleanly; remove the new key file and the vault before trying again")
		}
	}
	if err := instanceaccess.Create(accessPath, password); err != nil {
		return err
	}
	if _, err := io.WriteString(output, "\nInstallation created. Sign in on localhost and change this password before using Rootwell.\n"); err != nil {
		return errors.New("installation was created, but the final confirmation could not be shown")
	}
	return nil
}

func serve(dir, keyFile, assetsDir string) error {
	// #nosec G703 -- dir is a local operator CLI path, never an HTTP input.
	directory, err := os.Stat(dir)
	if err != nil || !directory.IsDir() || (runtime.GOOS != "windows" && directory.Mode().Perm()&0o077 != 0) {
		return errors.New("installation data directory must be private to its owner")
	}
	if err := keyOutsideData(dir, keyFile); err != nil {
		return err
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
	releaseOperation, err := instanceaccess.AcquireOperationLock(accessPath)
	if err != nil {
		return err
	}
	defer releaseOperation()
	var certificates *certstore.Store
	if custody() {
		key, err := vault.ReadKeyFile(keyFile)
		if err != nil {
			return errors.New("the instance key file could not be read; it must be a private 0600 file of this user")
		}
		v, err := vault.Open(dir, key)
		clear(key)
		if err != nil {
			return errors.New("the certificate vault did not open with this instance key")
		}
		defer v.Close()
		certificates = certstore.New(v)
	}
	gate, err := newGate(accessPath, assetsDir, localHost, certificates)
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
	listeners, err := listenLoopback(4180)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "Rootwell is available at http://localhost:4180 (this host only)")
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
