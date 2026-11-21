//go:build linux

package main

import (
	"syscall"
	"testing"
)

func TestHardenProcessDisablesCoreDumpsAndDumpability(t *testing.T) {
	if err := hardenProcess(); err != nil {
		t.Fatal(err)
	}
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &limit); err != nil || limit.Cur != 0 || limit.Max != 0 {
		t.Fatalf("core limit %+v, %v", limit, err)
	}
	dumpable, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
	if errno != 0 || dumpable != 0 {
		t.Fatalf("dumpable %d, %v", dumpable, errno)
	}
}
