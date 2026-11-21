//go:build linux

package main

import (
	"errors"
	"syscall"
)

// hardenProcess keeps keys, passwords and tokens out of core dumps and out of
// reach of same-user debuggers before any secret is read (audit RW-11).
// PR_SET_DUMPABLE 0 also makes /proc/<pid>/mem and ptrace attach need root.
func hardenProcess() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		return errors.New("core dumps could not be disabled")
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return errors.New("the process could not be made non-dumpable")
	}
	return nil
}
