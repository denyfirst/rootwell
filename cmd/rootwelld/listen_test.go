package main

import (
	"net"
	"strconv"
	"testing"
)

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestListenLoopbackHoldsBothAddresses(t *testing.T) {
	port := freeLoopbackPort(t)
	listeners, err := listenLoopback(port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	squat, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err == nil {
		_ = squat.Close()
		t.Fatal("another program could still take the IPv6 loopback port")
	}
	if len(listeners) != 2 {
		t.Skip("this host has no IPv6 loopback")
	}
}

func TestListenLoopbackRefusesATakenIPv6Port(t *testing.T) {
	port := freeLoopbackPort(t)
	squat, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err != nil {
		t.Skip("this host has no IPv6 loopback")
	}
	defer squat.Close()
	listeners, err := listenLoopback(port)
	if err == nil {
		for _, listener := range listeners {
			_ = listener.Close()
		}
		t.Fatal("started while another program held the IPv6 loopback port")
	}
	// The refused start must not keep the IPv4 port either.
	v4, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal("the refused start left the IPv4 port open:", err)
	}
	_ = v4.Close()
}
