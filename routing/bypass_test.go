//go:build linux || android

// Tests for issue #7: redirect-gateway routing loop.
//
// When redirect-gateway is active the daemon installed a 0.0.0.0/0 default
// route via tun0 without first protecting the VPN server's own IP. The kernel
// then re-evaluated the existing TCP socket's route, found tun0 as the best
// path, and the VPN traffic looped back through the tunnel — killing the
// connection with "broken pipe" within seconds.
//
// The fix adds a /32 bypass route for the VPN server IP before the default
// route is applied, using LookupGateway + AddBypassRoute.  DeleteBypassRoute
// removes it on disconnect.
//
// These tests cover:
//   1. parseRouteGateway — the netlink response parser (pure unit test, no root)
//   2. LookupGateway — loopback sanity check (no root)
//   3. AddBypassRoute / DeleteBypassRoute — real netlink writes (root required)
package routing

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// buildFakeRouteReply builds a minimal RTM_NEWROUTE netlink response.
// When gw is non-nil an RTA_GATEWAY attribute is appended; otherwise the
// response models a direct-link route (no gateway).
func buildFakeRouteReply(gw net.IP) []byte {
	const rtmsgSize = 12

	var gwAttr []byte
	if gw != nil {
		gwAttr = nlAttr(unix.RTA_GATEWAY, gw.To4())
	}

	totalLen := nlmsgHdrSize + rtmsgSize + len(gwAttr)
	buf := make([]byte, totalLen)

	binary.LittleEndian.PutUint32(buf[0:4], uint32(totalLen)) // nlmsg_len
	binary.LittleEndian.PutUint16(buf[4:6], unix.RTM_NEWROUTE) // nlmsg_type
	buf[nlmsgHdrSize] = unix.AF_INET                            // rtmsg.Family

	copy(buf[nlmsgHdrSize+rtmsgSize:], gwAttr)
	return buf
}

// TestParseRouteGateway_WithGateway verifies that a netlink response
// containing RTA_GATEWAY is decoded to the correct IP.
func TestParseRouteGateway_WithGateway(t *testing.T) {
	want := net.IPv4(192, 168, 1, 1)
	buf := buildFakeRouteReply(want)

	got, err := parseRouteGateway(buf)
	if err != nil {
		t.Fatalf("parseRouteGateway: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil gateway, got nil")
	}
	if !got.Equal(want) {
		t.Errorf("gateway: got %s, want %s", got, want)
	}
}

// TestParseRouteGateway_NoGateway verifies that a response without RTA_GATEWAY
// (direct-link route) returns nil without error.
func TestParseRouteGateway_NoGateway(t *testing.T) {
	buf := buildFakeRouteReply(nil)

	got, err := parseRouteGateway(buf)
	if err != nil {
		t.Fatalf("parseRouteGateway: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for direct-link route, got %s", got)
	}
}

// TestLookupGateway_Loopback verifies that looking up the loopback address
// does not return an error.  127.0.0.1 is a local/loopback address so there
// is no gateway (returns nil), but the call must not fail.
func TestLookupGateway_Loopback(t *testing.T) {
	_, err := LookupGateway(net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("LookupGateway(127.0.0.1): %v", err)
	}
}

// TestAddDeleteBypassRoute verifies that AddBypassRoute installs a /32 host
// route for an RFC-5737 test address, that a second call is idempotent
// (EEXIST treated as success), and that DeleteBypassRoute removes it with the
// same idempotency guarantee.
//
// Requires root (CAP_NET_ADMIN).  Skipped automatically otherwise.
func TestAddDeleteBypassRoute(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root — re-run with sudo or in a privileged network namespace")
	}

	// Discover a real gateway so the kernel accepts the new route.
	// If there is no default gateway (direct-link host) the test is not
	// applicable and is skipped.
	gw, err := LookupGateway(net.IPv4(1, 1, 1, 1))
	if err != nil {
		t.Skipf("LookupGateway: %v — skipping netlink write test", err)
	}
	if gw == nil {
		t.Skip("no default gateway — direct-link host, bypass route not applicable")
	}

	// 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — reserved, safe to use in tests.
	serverIP := net.IPv4(203, 0, 113, 42)

	if err := AddBypassRoute(serverIP, gw); err != nil {
		t.Fatalf("AddBypassRoute: %v", err)
	}
	// Second call must be idempotent (EEXIST → nil).
	if err := AddBypassRoute(serverIP, gw); err != nil {
		t.Fatalf("AddBypassRoute (idempotent): %v", err)
	}

	if err := DeleteBypassRoute(serverIP, gw); err != nil {
		t.Fatalf("DeleteBypassRoute: %v", err)
	}
	// Second call must be idempotent (ESRCH → nil).
	if err := DeleteBypassRoute(serverIP, gw); err != nil {
		t.Fatalf("DeleteBypassRoute (idempotent): %v", err)
	}
}
