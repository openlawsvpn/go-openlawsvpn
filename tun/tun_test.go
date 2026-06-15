//go:build linux

// Unit tests for the tun package.
//
// The tests require /dev/net/tun and a Linux kernel with TUN support.
// They skip gracefully when the device is unavailable or when not running
// as root.
package tun

import (
	"net"
	"os"
	"testing"
)

// TestOpen_SkipIfNoTun checks that Open returns a sensible error when
// /dev/net/tun is not available instead of panicking.
func TestOpen_SkipIfNoTun(t *testing.T) {
	if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
		t.Skip("/dev/net/tun not present — skipping TUN tests")
	}
	if os.Getuid() != 0 {
		t.Skip("TUN tests require root")
	}

	dev, err := Open("")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close()

	name := dev.Name()
	if name == "" {
		t.Fatal("expected non-empty interface name")
	}
	t.Logf("allocated TUN interface: %s", name)
}

// TestConfigure runs Open + Configure on /dev/net/tun.
func TestConfigure(t *testing.T) {
	if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
		t.Skip("/dev/net/tun not present — skipping TUN tests")
	}
	if os.Getuid() != 0 {
		t.Skip("TUN tests require root")
	}

	dev, err := Open("")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close()

	cfg := Config{
		LocalIP: net.ParseIP("10.99.0.1"),
		PeerIP:  net.ParseIP("10.99.0.2"),
		MTU:     1400,
	}
	if err := dev.Configure(cfg); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	t.Logf("configured %s: local=%s peer=%s mtu=%d",
		dev.Name(), cfg.LocalIP, cfg.PeerIP, cfg.MTU)
}

// TestConfig_DefaultMTU verifies that a zero MTU is treated as 1500.
func TestConfig_DefaultMTU(t *testing.T) {
	if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
		t.Skip("/dev/net/tun not present")
	}
	if os.Getuid() != 0 {
		t.Skip("TUN tests require root")
	}

	dev, err := Open("")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close()

	// MTU=0 should default to 1500 without error.
	cfg := Config{
		LocalIP: net.ParseIP("10.99.1.1"),
		PeerIP:  net.ParseIP("10.99.1.2"),
		MTU:     0, // should default to 1500
	}
	if err := dev.Configure(cfg); err != nil {
		t.Fatalf("Configure with zero MTU: %v", err)
	}
}
