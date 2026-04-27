package main

import (
	"net"
	"testing"
)

// TestOutboundIPReturnsNonLoopback verifies that outboundIP returns a valid,
// non-loopback IP when the machine has network connectivity.
func TestOutboundIPReturnsNonLoopback(t *testing.T) {
	ip := outboundIP()
	if ip == "" {
		t.Skip("no outbound route available in this environment")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("outboundIP returned unparseable value %q", ip)
	}
	if parsed.IsLoopback() {
		t.Errorf("outboundIP returned loopback address %q", ip)
	}
	if parsed.IsUnspecified() {
		t.Errorf("outboundIP returned unspecified address %q", ip)
	}
}

// TestOutboundIPIsStable verifies that repeated calls return the same value.
func TestOutboundIPIsStable(t *testing.T) {
	a := outboundIP()
	b := outboundIP()
	if a != b {
		t.Errorf("outboundIP unstable: %q != %q", a, b)
	}
}
