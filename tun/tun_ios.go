//go:build ios

// iOS TUN support via NEPacketTunnelProvider.
//
// On iOS apps cannot open /dev/net/tun directly. Instead the Network Extension
// framework creates the TUN interface and exposes the raw file descriptor via
// a private KVC key on NEPacketTunnelFlow:
//
//	fd := (self.packetFlow as AnyObject).value(forKey: "mTunFileDescriptor") as! Int32
//
// The Swift PacketTunnelProvider passes this fd to VpnMobileClient.establishTUN,
// which calls OpenFd here to wrap it for use by the Go engine.
package tun

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Config holds the parameters used to configure a TUN interface.
// On iOS these are informational only — NEPacketTunnelNetworkSettings has
// already been applied by setTunnelNetworkSettings before handing us the fd.
type Config struct {
	LocalIP net.IP
	PeerIP  net.IP
	Mask    net.IPMask
	MTU     int
}

// Device represents an open TUN interface.
type Device struct {
	file *os.File
	name string
}

// Name returns the interface name ("utun0" on iOS/macOS).
func (d *Device) Name() string { return d.name }

// File returns the underlying *os.File for reading and writing raw IP packets.
func (d *Device) File() *os.File { return d.file }

// Close closes the TUN device file descriptor.
func (d *Device) Close() error { return d.file.Close() }

// Configure is a no-op on iOS: NEPacketTunnelNetworkSettings already configured
// the interface before handing us the fd.
func (d *Device) Configure(_ Config) error { return nil }

// OpenFd wraps a TUN file descriptor provided by iOS's NEPacketTunnelFlow.
//
// The fd is the value extracted from packetFlow via the mTunFileDescriptor KVC
// key (a private but App-Store-approved API used by WireGuard-iOS since 2019).
// The interface is fully configured (IP address, routes, DNS) by the Swift
// PacketTunnelProvider via setTunnelNetworkSettings before this call.
//
// OpenFd sets O_NONBLOCK on the fd so Go's runtime poller can manage it,
// then wraps it with os.NewFile.
func OpenFd(fd int) (*Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("tun: invalid fd %d", fd)
	}
	// O_NONBLOCK is required so Go's runtime poller can use kqueue on the fd.
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("tun: SetNonblock: %w", err)
	}
	f := os.NewFile(uintptr(fd), "packettunnel-tun")
	if f == nil {
		return nil, fmt.Errorf("tun: os.NewFile returned nil for fd %d", fd)
	}
	return &Device{file: f, name: "utun0"}, nil
}
