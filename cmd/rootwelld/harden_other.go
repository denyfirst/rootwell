//go:build !linux

package main

// Secret custody runs on Linux only; development builds elsewhere have no
// equivalent process setting to apply.
func hardenProcess() error { return nil }
