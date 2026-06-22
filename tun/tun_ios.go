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

// utun protocol-family header constants (network byte order). The iOS NE fd we
// receive from the Swift socket scan is a raw utun control socket — the same
// kernel interface as macOS — so it prepends a 4-byte AF_ header to every packet
// read and requires one on every packet written. (NEPacketTunnelFlow would hide
// this, but we read the fd directly.) AF_INET = 2, AF_INET6 = 30 on Darwin.
var (
	utunPktInfoAFInet  = [4]byte{0x00, 0x00, 0x00, 0x02}
	utunPktInfoAFInet6 = [4]byte{0x00, 0x00, 0x00, 0x1e}
)

// Read reads one IP packet from the utun device, stripping the 4-byte AF header.
func (d *Device) Read(buf []byte) (int, error) {
	tmp := make([]byte, len(buf)+4)
	n, err := d.file.Read(tmp)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, nil
	}
	return copy(buf, tmp[4:n]), nil
}

// Write writes one IP packet to the utun device, prepending the 4-byte AF header
// matching the packet's IP version.
func (d *Device) Write(pkt []byte) (int, error) {
	hdr := utunPktInfoAFInet
	if len(pkt) > 0 && pkt[0]>>4 == 6 {
		hdr = utunPktInfoAFInet6
	}
	buf := make([]byte, 4+len(pkt))
	copy(buf[:4], hdr[:])
	copy(buf[4:], pkt)
	_, err := d.file.Write(buf)
	return len(pkt), err
}

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
