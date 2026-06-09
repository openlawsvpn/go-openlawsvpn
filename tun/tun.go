//go:build !android && !ios && !darwin

// Package tun provides a TUN network interface for Linux.
//
// It opens /dev/net/tun via ioctl and configures the resulting interface
// with an IP address, peer address, and MTU using the SIOCSIFADDR,
// SIOCSIFDSTADDR, SIOCSIFMTU, and SIOCSIFFLAGS ioctls — all without CGo.
//
// Only Linux is supported (CGO_ENABLED=0, golang.org/x/sys/unix).
//
// Typical usage:
//
//	dev, err := tun.Open("tun0")         // allocate /dev/net/tun
//	if err != nil { ... }
//	defer dev.Close()
//
//	if err := dev.Configure(tun.Config{
//	    LocalIP:  net.ParseIP("10.8.0.6"),
//	    PeerIP:   net.ParseIP("10.8.0.5"),
//	    MTU:      1500,
//	}); err != nil { ... }
//
//	// dev.File() is an *os.File; read/write raw IPv4 packets from it.
package tun

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ifReq is the ifreq structure used by TUN/TAP ioctl calls.
// The name field is [unix.IFNAMSIZ]byte (16 bytes); the union
// field that follows is at least 16 bytes wide and carries
// different data depending on the ioctl.
//
// We define it here instead of relying on unix.Ifreq because the
// kernel TUNSETIFF ioctl expects flags in the second word of the
// union while the socket ioctls (SIOCSIFADDR etc.) expect a
// sockaddr_in — so we use two separate layouts.

// ifreqFlags holds an ifreq with the flags word (used by TUNSETIFF).
type ifreqFlags struct {
	name  [unix.IFNAMSIZ]byte
	flags int16
	_     [22]byte // padding to reach struct size of 40 bytes
}

// ifreqSockAddr holds an ifreq with a sockaddr_in (used by SIOCSIFADDR etc.).
type ifreqSockAddr struct {
	name [unix.IFNAMSIZ]byte
	addr unix.RawSockaddrInet4
	_    [8]byte // padding
}

// ifreqInt holds an ifreq with a single int32 value (used by SIOCSIFMTU).
type ifreqInt struct {
	name [unix.IFNAMSIZ]byte
	val  int32
	_    [20]byte
}

// TUN ioctls and flags (linux/if_tun.h).
const (
	tunSetIFF = 0x400454ca // TUNSETIFF
	iffTUN    = 0x0001     // IFF_TUN
	iffNoPi   = 0x1000     // IFF_NO_PI — omit 4-byte packet-info header
)

// Socket ioctls (linux/sockios.h).
const (
	siocSIFAddr    = 0x8916 // SIOCSIFADDR
	siocSIFDstAddr = 0x8918 // SIOCSIFDSTADDR  (point-to-point peer)
	siocSIFNetmask = 0x891c // SIOCSIFNETMASK  (subnet mask)
	siocSIFFlags   = 0x8914 // SIOCSIFFLAGS
	siocSIFMTU     = 0x8922 // SIOCSIFMTU
	siocGIFFlags   = 0x8913 // SIOCGIFFLAGS
)

// Interface flags (linux/if.h).
const (
	iffUp      = 0x1
	iffRunning = 0x40
)

// Config holds the parameters used to configure a TUN interface.
type Config struct {
	// LocalIP is the IP address assigned to this end of the tunnel.
	LocalIP net.IP
	// PeerIP is the P2P peer address for net30 topology.
	// Mutually exclusive with Mask — set one or the other.
	PeerIP net.IP
	// Mask is the subnet mask for subnet topology.
	// When set, the interface is configured with SIOCSIFNETMASK instead of
	// SIOCSIFDSTADDR so the kernel treats it as a regular (non-P2P) subnet.
	Mask net.IPMask
	// MTU is the maximum transmission unit for the interface (default 1500).
	// A value of 0 means use 1500.
	MTU int
}

// Device represents an open TUN interface.
type Device struct {
	file *os.File
	name string
}

// Open allocates a TUN interface.
//
// If ifaceName is empty, the kernel assigns a name (e.g. "tun0").
// The interface is not yet configured; call Configure before writing packets.
//
// Opening sequence (mirrors wireguard-go tun/tun_linux.go):
//  1. Open /dev/net/tun with unix.Open (O_RDWR|O_CLOEXEC) — raw syscall,
//     no Go runtime involvement yet.
//  2. Issue TUNSETIFF directly on the raw fd.
//  3. Set O_NONBLOCK on the raw fd so Go's runtime poller can use epoll.
//  4. Wrap with os.NewFile — this registers the fd with epoll and enables
//     deadline-based reads.
//
// Using os.OpenFile instead of unix.Open causes Go to register the fd with
// epoll before TUNSETIFF runs. On some kernels the /dev/net/tun char device
// is not epoll-able until a TUN interface is attached; epoll registration
// fails silently, and all subsequent os.File.Read calls return
// poll.ErrNotPollable ("read /dev/net/tun: not pollable") immediately.
func Open(ifaceName string) (*Device, error) {
	// Step 1: raw open — no Go poller registration yet.
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open /dev/net/tun: %w", err)
	}

	// Step 2: TUNSETIFF — attach a TUN interface to the fd.
	var req ifreqFlags
	if ifaceName != "" {
		copy(req.name[:], ifaceName)
	}
	req.flags = iffTUN | iffNoPi
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), tunSetIFF, uintptr(unsafe.Pointer(&req))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: TUNSETIFF: %w", errno)
	}

	// Step 3: set O_NONBLOCK so Go's runtime poller (epoll) can manage the fd.
	// Must be done AFTER TUNSETIFF — the kernel only allows epoll on a TUN fd
	// once an interface is attached.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: SetNonblock: %w", err)
	}

	// Step 4: hand the fd to Go's runtime. os.NewFile registers it with epoll,
	// enabling SetReadDeadline and non-blocking I/O via the runtime poller.
	f := os.NewFile(uintptr(fd), "/dev/net/tun")
	if f == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: os.NewFile returned nil")
	}

	name := unix.ByteSliceToString(req.name[:])
	return &Device{file: f, name: name}, nil
}

// Name returns the kernel interface name, e.g. "tun0".
func (d *Device) Name() string { return d.name }

// File returns the underlying *os.File for reading and writing raw IP packets.
func (d *Device) File() *os.File { return d.file }

// Close closes the TUN device file descriptor.
// The kernel automatically removes the interface when the last fd is closed.
func (d *Device) Close() error { return d.file.Close() }

// Configure sets the local IP, peer IP, MTU, and brings the interface up.
// It must be called after Open and before writing packets.
func (d *Device) Configure(cfg Config) error {
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}

	// We need an AF_INET socket to issue the SIOCS* ioctls.
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("tun: socket: %w", err)
	}
	defer unix.Close(sock)

	// SIOCSIFADDR — set local address.
	if cfg.LocalIP != nil {
		if err := d.setAddr(sock, siocSIFAddr, cfg.LocalIP); err != nil {
			return fmt.Errorf("tun: SIOCSIFADDR: %w", err)
		}
	}

	if cfg.Mask != nil {
		// Subnet topology: set the subnet mask via SIOCSIFNETMASK.
		// The kernel will set up the connected subnet route automatically.
		maskIP := net.IP(cfg.Mask)
		if err := d.setAddr(sock, siocSIFNetmask, maskIP); err != nil {
			return fmt.Errorf("tun: SIOCSIFNETMASK: %w", err)
		}
	} else if cfg.PeerIP != nil {
		// Net30 topology: set the P2P peer address via SIOCSIFDSTADDR.
		if err := d.setAddr(sock, siocSIFDstAddr, cfg.PeerIP); err != nil {
			return fmt.Errorf("tun: SIOCSIFDSTADDR: %w", err)
		}
	}

	// SIOCSIFMTU — set MTU.
	if err := d.setMTU(sock, cfg.MTU); err != nil {
		return fmt.Errorf("tun: SIOCSIFMTU: %w", err)
	}

	// SIOCSIFFLAGS — bring the interface up.
	if err := d.setFlags(sock, iffUp|iffRunning); err != nil {
		return fmt.Errorf("tun: SIOCSIFFLAGS: %w", err)
	}

	return nil
}

// setAddr issues a SIOCSIFADDR or SIOCSIFDSTADDR ioctl with the given IPv4 address.
func (d *Device) setAddr(sock int, ioctlNum uintptr, ip net.IP) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv6 not supported (got %s)", ip)
	}
	var req ifreqSockAddr
	copy(req.name[:], d.name)
	req.addr.Family = unix.AF_INET
	copy(req.addr.Addr[:], ip4)

	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(sock),
		ioctlNum,
		uintptr(unsafe.Pointer(&req)),
	); errno != 0 {
		return errno
	}
	return nil
}

// setMTU issues SIOCSIFMTU with the given MTU value.
func (d *Device) setMTU(sock int, mtu int) error {
	var req ifreqInt
	copy(req.name[:], d.name)
	req.val = int32(mtu)

	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(sock),
		siocSIFMTU,
		uintptr(unsafe.Pointer(&req)),
	); errno != 0 {
		return errno
	}
	return nil
}

// setFlags issues SIOCSIFFLAGS to set the given interface flags.
// It first reads the current flags with SIOCGIFFLAGS so pre-existing
// flags (e.g. IFF_POINTOPOINT set by the kernel for a TUN device) are
// preserved.
func (d *Device) setFlags(sock int, extraFlags int16) error {
	var req ifreqFlags
	copy(req.name[:], d.name)

	// Read current flags.
	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(sock),
		siocGIFFlags,
		uintptr(unsafe.Pointer(&req)),
	); errno != 0 {
		return errno
	}

	req.flags |= extraFlags

	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(sock),
		siocSIFFlags,
		uintptr(unsafe.Pointer(&req)),
	); errno != 0 {
		return errno
	}
	return nil
}
