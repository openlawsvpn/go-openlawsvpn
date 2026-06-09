//go:build darwin && !ios

// Stubs for Linux netlink functions on macOS.
// On macOS, routing is managed by NEPacketTunnelNetworkSettings; the Go layer
// never calls ApplyRoutes or DeleteRoutes directly.
package routing

import "net"

// ApplyRoutes is a no-op on macOS — routes are applied via setTunnelNetworkSettings.
func ApplyRoutes(_ *PushOptions, _ int) error { return nil }

// DeleteRoutes is a no-op on macOS — the OS tears down routes when the tunnel stops.
func DeleteRoutes(_ *PushOptions, _ int) error { return nil }

// AddIPv6Addr is a no-op on macOS — IPv6 is configured via NEIPv6Settings.
func AddIPv6Addr(_ int, _ net.IP, _ int) error { return nil }

// InterfaceIndex is a no-op on macOS — interface management is handled by the OS.
func InterfaceIndex(_ string) (int, error) { return 0, nil }
