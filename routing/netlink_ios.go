//go:build ios

// Stubs for Linux netlink functions on iOS.
// On iOS, routing is managed by NEPacketTunnelNetworkSettings; the Go layer
// never calls ApplyRoutes or DeleteRoutes directly.
package routing

import "net"

// ApplyRoutes is a no-op on iOS — routes are applied via setTunnelNetworkSettings.
func ApplyRoutes(_ *PushOptions, _ int) error { return nil }

// DeleteRoutes is a no-op on iOS — the OS tears down routes when the tunnel stops.
func DeleteRoutes(_ *PushOptions, _ int) error { return nil }

// AddIPv6Addr is a no-op on iOS — IPv6 is configured via NEIPv6Settings.
func AddIPv6Addr(_ int, _ net.IP, _ int) error { return nil }

// InterfaceIndex is a no-op on iOS — interface management is handled by the OS.
func InterfaceIndex(_ string) (int, error) { return 0, nil }

// LookupGateway is a no-op on iOS — routing is managed by the OS.
func LookupGateway(_ net.IP) (net.IP, error) { return nil, nil }

// AddBypassRoute is a no-op on iOS — VPN socket bypass is handled by the OS.
func AddBypassRoute(_, _ net.IP) error { return nil }

// DeleteBypassRoute is a no-op on iOS — routes are torn down by the OS.
func DeleteBypassRoute(_, _ net.IP) error { return nil }
