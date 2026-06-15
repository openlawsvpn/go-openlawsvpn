//go:build darwin && !ios

// Package tun provides macOS TUN device support via two paths:
//
// Path A — Native utun (CLI, Homebrew, GitHub Actions):
// Open() allocates a utun interface using SYSPROTO_CONTROL +
// com.apple.net.utun_control, the same mechanism used by WireGuard-go and the
// macOS openvpn3 client. Requires root / sudo; no entitlements needed.
//
// Path B — Network Extension (GUI app):
// OpenFd() wraps the file descriptor provided by NEPacketTunnelFlow via the
// private mTunFileDescriptor KVC key. The OS already configured the interface
// via setTunnelNetworkSettings; Configure() is a no-op on this path.
package tun

import (
	"fmt"
	"net"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// utun socket constants (XNU bsd/net/if_utun.h).
const (
	utunCtlName = "com.apple.net.utun_control"
	// sysprotoControl is the protocol number for AF_SYSTEM kernel control sockets.
	// Equivalent to SYSPROTO_CONTROL in <sys/kern_control.h> (value = 2).
	sysprotoControl = 2
	// utunOptIfname retrieves the interface name after connecting to the control socket.
	utunOptIfname = 2
)

// Config holds the parameters used to configure a TUN interface.
//
// On Path A (CLI) Configure() uses these values to call ifconfig(8) equivalents
// via ioctl. On Path B (GUI) these are informational only — NEPacketTunnelNetworkSettings
// has already been applied by setTunnelNetworkSettings before handing us the fd.
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

// Name returns the kernel interface name (e.g. "utun3").
func (d *Device) Name() string { return d.name }

// File returns the underlying *os.File for reading and writing raw IP packets.
func (d *Device) File() *os.File { return d.file }

// Close closes the TUN device file descriptor.
func (d *Device) Close() error { return d.file.Close() }

// Configure sets the local IP, peer IP/mask, and MTU on the utun interface.
//
// On Path B (Network Extension) this is a no-op — the Swift PacketTunnelProvider
// already applied all settings via setTunnelNetworkSettings.
//
// On Path A (CLI) this calls the SIOCSIFADDR, SIOCSIFDSTADDR/SIOCSIFNETMASK,
// SIOCSIFMTU, and SIOCSIFFLAGS ioctls through an AF_INET socket, same as the
// Linux path but using the BSD ioctl layout.
func (d *Device) Configure(cfg Config) error {
	if d.name == "packettunnel-tun-macos" {
		// Path B: interface fully configured by NEPacketTunnelNetworkSettings.
		return nil
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("tun: socket: %w", err)
	}
	defer unix.Close(sock)

	if cfg.LocalIP != nil {
		if err := ifconfigAddr(sock, d.name, unix.SIOCSIFADDR, cfg.LocalIP); err != nil {
			return fmt.Errorf("tun: SIOCSIFADDR: %w", err)
		}
	}
	if cfg.Mask != nil {
		if err := ifconfigAddr(sock, d.name, unix.SIOCSIFNETMASK, net.IP(cfg.Mask)); err != nil {
			return fmt.Errorf("tun: SIOCSIFNETMASK: %w", err)
		}
	} else if cfg.PeerIP != nil {
		if err := ifconfigAddr(sock, d.name, unix.SIOCSIFDSTADDR, cfg.PeerIP); err != nil {
			return fmt.Errorf("tun: SIOCSIFDSTADDR: %w", err)
		}
	}
	if err := ifconfigMTU(sock, d.name, cfg.MTU); err != nil {
		return fmt.Errorf("tun: SIOCSIFMTU: %w", err)
	}
	if err := ifconfigUp(sock, d.name); err != nil {
		return fmt.Errorf("tun: SIOCSIFFLAGS: %w", err)
	}
	return nil
}

// Open allocates a utun interface using SYSPROTO_CONTROL.
//
// Requires root / sudo (no CAP_NET_ADMIN equivalent on macOS; root is required
// to create kernel control sockets). unit=0 asks the kernel to pick the next
// free interface number (utun0, utun1, …).
//
// Reference: WireGuard-go tun/tun_darwin.go; XNU bsd/net/if_utun.c.
func Open() (*Device, error) {
	// 1. Open a PF_SYSTEM / SYSPROTO_CONTROL socket.
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("tun: socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL): %w", err)
	}

	// 2. Resolve the kernel control ID for "com.apple.net.utun_control".
	info := unix.CtlInfo{}
	copy(info.Name[:], utunCtlName)
	if err := unix.IoctlCtlInfo(fd, &info); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: CTLIOCGINFO: %w", err)
	}

	// 3. Connect to the control socket; unit=0 → kernel picks interface number.
	addr := unix.SockaddrCtl{
		ID:   info.Id,
		Unit: 0,
	}
	if err := unix.Connect(fd, &addr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: connect utun_control: %w", err)
	}

	// 4. Read back the interface name assigned by the kernel ("utun3\x00…").
	var ifName [unix.IFNAMSIZ]byte
	ifNameLen := uint32(unix.IFNAMSIZ)
	if _, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		sysprotoControl,
		utunOptIfname,
		uintptr(unsafe.Pointer(&ifName)),
		uintptr(unsafe.Pointer(&ifNameLen)),
		0,
	); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: getsockopt UTUN_OPT_IFNAME: %w", errno)
	}
	name := strings.TrimRight(string(ifName[:]), "\x00")

	// 5. Set O_NONBLOCK so Go's runtime poller (kqueue) can manage the fd.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: SetNonblock: %w", err)
	}

	// 6. Hand the fd to Go's runtime (registers with kqueue).
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: os.NewFile returned nil")
	}
	return &Device{file: f, name: name}, nil
}

// OpenFd wraps a TUN file descriptor provided by macOS's NEPacketTunnelFlow.
//
// Path B only. The fd is extracted from packetFlow via the mTunFileDescriptor
// KVC key (a private but App-Store-approved API; WireGuard-macOS since 2019).
// The interface is already fully configured; Configure() is a no-op on this fd.
func OpenFd(fd int) (*Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("tun: invalid fd %d", fd)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("tun: SetNonblock: %w", err)
	}
	f := os.NewFile(uintptr(fd), "packettunnel-tun-macos")
	if f == nil {
		return nil, fmt.Errorf("tun: os.NewFile returned nil for fd %d", fd)
	}
	return &Device{file: f, name: "packettunnel-tun-macos"}, nil
}

// ifreqSockAddr is the BSD ifreq layout carrying a sockaddr_in.
type ifreqSockAddr struct {
	name [unix.IFNAMSIZ]byte
	addr unix.RawSockaddrInet4
	_    [8]byte
}

// ifreqInt is the BSD ifreq layout carrying a single int32 (MTU).
type ifreqInt struct {
	name [unix.IFNAMSIZ]byte
	val  int32
	_    [12]byte
}

// ifreqFlags is the BSD ifreq layout carrying interface flags.
type ifreqFlags struct {
	name  [unix.IFNAMSIZ]byte
	flags int16
	_     [12]byte
}

func ifconfigAddr(sock int, ifName string, ioctlNum uintptr, ip net.IP) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("IPv6 not supported (got %s)", ip)
	}
	var req ifreqSockAddr
	copy(req.name[:], ifName)
	req.addr.Family = unix.AF_INET
	copy(req.addr.Addr[:], ip4)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), ioctlNum, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return errno
	}
	return nil
}

func ifconfigMTU(sock int, ifName string, mtu int) error {
	var req ifreqInt
	copy(req.name[:], ifName)
	req.val = int32(mtu)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return errno
	}
	return nil
}

func ifconfigUp(sock int, ifName string) error {
	var req ifreqFlags
	copy(req.name[:], ifName)
	// Read current flags first.
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return errno
	}
	req.flags |= unix.IFF_UP | unix.IFF_RUNNING
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return errno
	}
	return nil
}
