//go:build integration

// Integration test: TUN device, routing, and DNS configuration.
//
// This test exercises the full Phase 4 stack end-to-end:
//
//  1. Opens a TUN device via /dev/net/tun.
//  2. Configures the device with the ifconfig addresses from a synthetic
//     PUSH_REPLY string.
//  3. Parses the PUSH_REPLY with routing.ParsePushReply and applies the
//     resulting routes to the kernel routing table via netlink.
//  4. Parses dhcp-option DNS with dns.ParsePushReply and writes a temporary
//     resolv.conf.
//  5. Verifies that:
//     - The TUN interface exists in /proc/net/if_inet6 or net.Interfaces().
//     - The expected routes appear in /proc/net/route.
//     - The resolv.conf was written with the correct nameservers.
//  6. Cleans up: deletes routes, closes TUN device, restores resolv.conf.
//
// Run with:
//
//	sudo go test -v -tags=integration -timeout=30s ./tun/
//
// Root (or CAP_NET_ADMIN + CAP_NET_RAW) is required.
package tun_test

import (
	"encoding/hex"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/dns"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
	"github.com/openlawsvpn/go-openlawsvpn/tun"
)

// syntheticPushReply is a realistic PUSH_REPLY string that the mock server
// would send after a successful auth.
const syntheticPushReply = "PUSH_REPLY," +
	"ifconfig 10.99.8.6 10.99.8.5," +
	"route 10.99.0.0 255.255.0.0," +
	"dhcp-option DNS 10.99.8.1," +
	"cipher AES-256-GCM\x00"

// TestTunnelUpRoutesApplied opens a TUN device, applies routes from a
// synthetic PUSH_REPLY, and verifies the kernel accepted them.
func TestTunnelUpRoutesApplied(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("integration test requires root (CAP_NET_ADMIN)")
	}
	if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
		t.Skip("/dev/net/tun not present")
	}

	// ---- 1. Open TUN device --------------------------------------------------
	dev, err := tun.Open("")
	if err != nil {
		t.Fatalf("tun.Open: %v", err)
	}
	defer dev.Close()
	t.Logf("opened TUN interface: %s", dev.Name())

	// ---- 2. Parse PUSH_REPLY for routing ------------------------------------
	routeOpts, err := routing.ParsePushReply(syntheticPushReply)
	if err != nil {
		t.Fatalf("routing.ParsePushReply: %v", err)
	}
	if routeOpts.Ifconfig == nil {
		t.Fatal("expected Ifconfig in PUSH_REPLY")
	}

	// ---- 3. Configure the TUN interface -------------------------------------
	cfg := tun.Config{
		LocalIP: routeOpts.Ifconfig.Local,
		PeerIP:  routeOpts.Ifconfig.Peer,
		MTU:     1500,
	}
	if err := dev.Configure(cfg); err != nil {
		t.Fatalf("dev.Configure: %v", err)
	}
	t.Logf("configured %s: local=%s peer=%s", dev.Name(), cfg.LocalIP, cfg.PeerIP)

	// ---- 4. Verify the interface exists -------------------------------------
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	var found bool
	for _, iface := range ifaces {
		if iface.Name == dev.Name() {
			found = true
			t.Logf("interface %s: flags=%v", iface.Name, iface.Flags)
			break
		}
	}
	if !found {
		t.Errorf("interface %s not found in net.Interfaces()", dev.Name())
	}

	// ---- 5. Apply routes ----------------------------------------------------
	ifIndex, err := routing.InterfaceIndex(dev.Name())
	if err != nil {
		t.Fatalf("InterfaceIndex: %v", err)
	}
	if err := routing.ApplyRoutes(routeOpts, ifIndex); err != nil {
		t.Fatalf("ApplyRoutes: %v", err)
	}
	t.Logf("routes applied for interface index %d", ifIndex)

	// ---- 6. Verify routes in /proc/net/route --------------------------------
	verifyRoute(t, "10.99.08", "10.99.00") // host route + net route

	// ---- 7. DNS configuration -----------------------------------------------
	dnsCfg, err := dns.ParsePushReply(syntheticPushReply)
	if err != nil {
		t.Fatalf("dns.ParsePushReply: %v", err)
	}
	if len(dnsCfg.Servers) == 0 {
		t.Fatal("expected at least one DNS server")
	}
	t.Logf("DNS servers: %v", dnsCfg.Servers)

	// Write resolv.conf to a temp file so we don't clobber the real one.
	tmpDir := t.TempDir()
	origPath := dns.ResolvConfPath
	dns.ResolvConfPath = tmpDir + "/resolv.conf"
	defer func() { dns.ResolvConfPath = origPath }()

	backupPath := tmpDir + "/resolv.conf.bak"
	if err := dns.BackupResolvConf(backupPath); err != nil {
		t.Fatalf("BackupResolvConf: %v", err)
	}
	if err := dns.ApplyResolvConf(dnsCfg); err != nil {
		t.Fatalf("ApplyResolvConf: %v", err)
	}

	data, err := os.ReadFile(dns.ResolvConfPath)
	if err != nil {
		t.Fatalf("read resolv.conf: %v", err)
	}
	t.Logf("resolv.conf:\n%s", data)
	if !strings.Contains(string(data), "nameserver 10.99.8.1") {
		t.Errorf("resolv.conf missing expected nameserver; got:\n%s", data)
	}
	managed, err := dns.IsManaged(dns.ResolvConfPath)
	if err != nil {
		t.Fatalf("IsManaged: %v", err)
	}
	if !managed {
		t.Error("resolv.conf should be marked as managed")
	}

	// ---- 8. Cleanup ---------------------------------------------------------
	if err := routing.DeleteRoutes(routeOpts, ifIndex); err != nil {
		t.Errorf("DeleteRoutes: %v", err)
	}
	if err := dns.RestoreResolvConf(backupPath); err != nil {
		t.Errorf("RestoreResolvConf: %v", err)
	}
	t.Log("cleanup complete")
}

// verifyRoute checks /proc/net/route to confirm that routes with the given
// hex-encoded destination prefixes appear.  The prefixes are matched as
// substring of the hex destination field (little-endian 32-bit).
//
// /proc/net/route columns (tab-separated):
//
//	Iface  Destination  Gateway  Flags  RefCnt  Use  Metric  Mask  MTU  Window  IRTT
func verifyRoute(t *testing.T, hexPrefixes ...string) {
	t.Helper()
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		t.Logf("cannot read /proc/net/route: %v (skipping route verification)", err)
		return
	}
	table := string(data)
	t.Logf("/proc/net/route:\n%s", table)

	// Convert 10.99.X.X to little-endian hex for matching.
	wantDests := procNetRouteDests([]string{"10.99.8.5", "10.99.0.0"})
	for _, want := range wantDests {
		if !strings.Contains(table, want) {
			t.Errorf("/proc/net/route: expected destination %s not found", want)
		}
	}
	_ = hexPrefixes // parameter kept for documentation
}

// procNetRouteDests converts a list of IPv4 addresses to the hex strings
// used as destination fields in /proc/net/route (little-endian, uppercase).
func procNetRouteDests(addrs []string) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		ip := net.ParseIP(a).To4()
		if ip == nil {
			continue
		}
		// /proc/net/route uses little-endian hex.
		le := [4]byte{ip[3], ip[2], ip[1], ip[0]}
		out = append(out, strings.ToUpper(hex.EncodeToString(le[:])))
	}
	return out
}
