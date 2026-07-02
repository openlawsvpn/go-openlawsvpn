//go:build linux || android

// Netlink route management for the routing package.
//
// ApplyRoutes adds the routes described by PushOptions to the kernel routing
// table.  It uses the Linux rtnetlink(7) socket interface via
// golang.org/x/sys/unix — no CGo, no external libraries.
//
// Route lifecycle:
//
//  1. If Ifconfig is present, add a host route to the peer address via the TUN
//     interface (so the P2P link is routable).
//  2. Add each explicit Route from the PUSH_REPLY.
//  3. If RedirectGateway is true, add a 0.0.0.0/0 default route via the peer.
//
// Reference: linux/rtnetlink.h, RFC 3549
package routing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// nlmsgHdrSize is the size of a netlink message header on the wire (16 bytes).
// Equivalent to NLMSG_HDRSIZE in linux/netlink.h.
const nlmsgHdrSize = 16

// ApplyRoutes programs the kernel routing table for the routes described by
// opts.  ifIndex is the kernel interface index of the TUN device (obtained
// from net.InterfaceByName(dev.Name()).Index or equivalent).
//
// For topology subnet, the TUN address is already configured as a /prefix
// address; only explicit routes and the default route are added.
//
// For topology net30, Linux automatically adds a /32 host route for the P2P
// peer when the interface is configured; EEXIST is tolerated for that route.
//
// This function requires CAP_NET_ADMIN.
func ApplyRoutes(opts *PushOptions, ifIndex int) error {
	if opts == nil {
		return nil
	}

	// --- IPv4 ---
	var defaultGW net.IP
	if opts.Ifconfig != nil {
		defaultGW = opts.Ifconfig.Gateway
	}

	if opts.Topology == TopologyNet30 && opts.Ifconfig != nil {
		if err := addRoute(ifIndex, opts.Ifconfig.Gateway, net.CIDRMask(32, 32), nil); err != nil {
			if !errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("routing: host route to peer %s: %w", opts.Ifconfig.Gateway, err)
			}
		}
	}

	for _, r := range opts.Routes {
		gw := r.Gateway
		if gw == nil {
			gw = defaultGW
		}
		if err := addRoute(ifIndex, r.Network, r.Mask, gw); err != nil {
			if !errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("routing: add route %s/%s: %w", r.Network, net.IP(r.Mask), err)
			}
		}
	}

	if opts.RedirectGateway {
		if err := addRoute(ifIndex, net.IPv4(0, 0, 0, 0), net.CIDRMask(0, 32), defaultGW); err != nil {
			if !errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("routing: add default route: %w", err)
			}
		}
	}

	// --- IPv6 ---
	var defaultGW6 net.IP
	if opts.Ifconfig6 != nil {
		defaultGW6 = opts.Ifconfig6.Gateway
	}

	for _, r := range opts.Routes6 {
		gw := r.Gateway
		if gw == nil {
			gw = defaultGW6
		}
		if err := addRoute6(ifIndex, r.Network, r.Prefix, gw); err != nil {
			if !errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("routing: add IPv6 route %s/%d: %w", r.Network, r.Prefix, err)
			}
		}
	}

	if opts.RedirectGateway6 {
		if err := addRoute6(ifIndex, net.IPv6zero, 0, defaultGW6); err != nil {
			if !errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("routing: add IPv6 default route: %w", err)
			}
		}
	}

	return nil
}

// DeleteRoutes removes the routes that ApplyRoutes would have added.
// It is the caller's responsibility to call DeleteRoutes on disconnect so
// that the system routing table is left in a clean state.
func DeleteRoutes(opts *PushOptions, ifIndex int) error {
	if opts == nil {
		return nil
	}

	var firstErr error
	save := func(err error) {
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}

	var defaultGW net.IP
	if opts.Ifconfig != nil {
		defaultGW = opts.Ifconfig.Gateway
	}

	if opts.Topology == TopologyNet30 && opts.Ifconfig != nil {
		save(delRoute(ifIndex, opts.Ifconfig.Gateway, net.CIDRMask(32, 32), nil))
	}
	for _, r := range opts.Routes {
		gw := r.Gateway
		if gw == nil {
			gw = defaultGW
		}
		save(delRoute(ifIndex, r.Network, r.Mask, gw))
	}
	if opts.RedirectGateway {
		save(delRoute(ifIndex, net.IPv4(0, 0, 0, 0), net.CIDRMask(0, 32), defaultGW))
	}

	var defaultGW6 net.IP
	if opts.Ifconfig6 != nil {
		defaultGW6 = opts.Ifconfig6.Gateway
	}
	for _, r := range opts.Routes6 {
		gw := r.Gateway
		if gw == nil {
			gw = defaultGW6
		}
		save(delRoute6(ifIndex, r.Network, r.Prefix, gw))
	}
	if opts.RedirectGateway6 {
		save(delRoute6(ifIndex, net.IPv6zero, 0, defaultGW6))
	}

	return firstErr
}

// ---- low-level netlink helpers -----------------------------------------------

// netlinkRouteMsg builds and sends a single RTM_NEWROUTE or RTM_DELROUTE
// netlink message for an IPv4 route.
//
// Layout: nlmsghdr (16B) + rtmsg (12B) + RTA_DST + RTA_GATEWAY [+ RTA_OIF]
// RTA_OIF is omitted when ifIndex == 0; the kernel resolves the output
// interface from the gateway in that case.
func netlinkRouteMsg(msgType uint16, flags uint16,
	ifIndex int, dst net.IP, mask net.IPMask, gw net.IP) error {

	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(sock)

	lsa := unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(sock, &lsa); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	ones, bits := mask.Size()
	if bits != 32 {
		return fmt.Errorf("only IPv4 masks supported (got bits=%d)", bits)
	}

	rtMsg := unix.RtMsg{
		Family:   unix.AF_INET,
		Dst_len:  uint8(ones),
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_STATIC,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	if ones == 32 && gw == nil {
		rtMsg.Scope = unix.RT_SCOPE_LINK
	}

	dst4 := dst.To4()
	rtaDst := nlAttr(unix.RTA_DST, dst4)

	var rtaOIF []byte
	if ifIndex > 0 {
		var oifBuf [4]byte
		binary.LittleEndian.PutUint32(oifBuf[:], uint32(ifIndex))
		rtaOIF = nlAttr(unix.RTA_OIF, oifBuf[:])
	}

	var rtaGW []byte
	if gw != nil {
		rtaGW = nlAttr(unix.RTA_GATEWAY, gw.To4())
	}

	payload := marshalRtMsg(rtMsg)
	payload = append(payload, rtaDst...)
	payload = append(payload, rtaGW...)
	payload = append(payload, rtaOIF...)

	return sendNetlinkMsg(sock, msgType, flags, payload)
}

// netlinkRouteMsg6 builds and sends a single RTM_NEWROUTE or RTM_DELROUTE
// netlink message for an IPv6 route.
func netlinkRouteMsg6(msgType uint16, flags uint16,
	ifIndex int, dst net.IP, prefixLen int, gw net.IP) error {

	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(sock)

	lsa := unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(sock, &lsa); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	rtMsg := unix.RtMsg{
		Family:   unix.AF_INET6,
		Dst_len:  uint8(prefixLen),
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_STATIC,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	if prefixLen == 128 && gw == nil {
		rtMsg.Scope = unix.RT_SCOPE_LINK
	}

	dst16 := dst.To16()
	rtaDst := nlAttr(unix.RTA_DST, dst16)

	var oifBuf [4]byte
	binary.LittleEndian.PutUint32(oifBuf[:], uint32(ifIndex))
	rtaOIF := nlAttr(unix.RTA_OIF, oifBuf[:])

	var rtaGW []byte
	if gw != nil {
		rtaGW = nlAttr(unix.RTA_GATEWAY, gw.To16())
	}

	payload := marshalRtMsg(rtMsg)
	payload = append(payload, rtaDst...)
	payload = append(payload, rtaGW...)
	payload = append(payload, rtaOIF...)

	return sendNetlinkMsg(sock, msgType, flags, payload)
}

// sendNetlinkMsg frames payload in an nlmsghdr and sends it, then reads the ACK.
// NLM_F_ACK ensures the kernel always sends NLMSG_ERROR (errno==0 on success).
func sendNetlinkMsg(sock int, msgType, flags uint16, payload []byte) error {
	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  msgType,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | flags,
		Seq:   1,
		Pid:   uint32(unix.Getpid()),
	}
	msg := marshalNlHdr(hdr)
	msg = append(msg, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}
	ksa := unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(sock, msg, 0, &ksa); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(sock, buf, 0)
	if err != nil {
		return fmt.Errorf("netlink recv: %w", err)
	}
	return parseNlError(buf[:n])
}

// addRoute adds an IPv4 route via RTM_NEWROUTE.
func addRoute(ifIndex int, dst net.IP, mask net.IPMask, gw net.IP) error {
	return netlinkRouteMsg(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
		ifIndex, dst, mask, gw)
}

// delRoute removes an IPv4 route via RTM_DELROUTE.
func delRoute(ifIndex int, dst net.IP, mask net.IPMask, gw net.IP) error {
	return netlinkRouteMsg(unix.RTM_DELROUTE, 0, ifIndex, dst, mask, gw)
}

// LookupGateway returns the gateway IP for the best route to dst in the main
// routing table.  Returns (nil, nil) when the route is a direct link route
// (no gateway — dst is on a directly connected subnet).
func LookupGateway(dst net.IP) (net.IP, error) {
	dst4 := dst.To4()
	if dst4 == nil {
		return nil, fmt.Errorf("routing: LookupGateway: IPv4 address required, got %v", dst)
	}

	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("routing: lookup gateway: socket: %w", err)
	}
	defer unix.Close(sock)

	lsa := unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(sock, &lsa); err != nil {
		return nil, fmt.Errorf("routing: lookup gateway: bind: %w", err)
	}

	rtMsg := unix.RtMsg{
		Family:  unix.AF_INET,
		Dst_len: 32,
		Table:   unix.RT_TABLE_MAIN,
	}
	rtaDst := nlAttr(unix.RTA_DST, dst4)
	payload := marshalRtMsg(rtMsg)
	payload = append(payload, rtaDst...)

	hdr := unix.NlMsghdr{
		Len:   uint32(nlmsgHdrSize + len(payload)),
		Type:  unix.RTM_GETROUTE,
		Flags: unix.NLM_F_REQUEST,
		Seq:   2,
		Pid:   uint32(unix.Getpid()),
	}
	msg := marshalNlHdr(hdr)
	msg = append(msg, payload...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}

	ksa := unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(sock, msg, 0, &ksa); err != nil {
		return nil, fmt.Errorf("routing: lookup gateway: send: %w", err)
	}

	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(sock, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("routing: lookup gateway: recv: %w", err)
	}

	return parseRouteGateway(buf[:n])
}

// parseRouteGateway extracts RTA_GATEWAY from a single RTM_GETROUTE response.
// Returns (nil, nil) for direct link routes (no gateway attribute).
func parseRouteGateway(buf []byte) (net.IP, error) {
	if len(buf) < nlmsgHdrSize {
		return nil, fmt.Errorf("routing: lookup gateway: short response")
	}
	msgType := binary.LittleEndian.Uint16(buf[4:6])
	if msgType == unix.NLMSG_ERROR {
		if len(buf) < nlmsgHdrSize+4 {
			return nil, fmt.Errorf("routing: lookup gateway: error response too short")
		}
		errno := int32(binary.LittleEndian.Uint32(buf[nlmsgHdrSize:]))
		if errno != 0 {
			return nil, fmt.Errorf("routing: lookup gateway: %w", syscall.Errno(-errno))
		}
		return nil, nil
	}
	const rtmsgSize = 12
	if len(buf) < nlmsgHdrSize+rtmsgSize {
		return nil, nil
	}
	attrs := buf[nlmsgHdrSize+rtmsgSize:]
	for len(attrs) >= 4 {
		attrLen := int(binary.LittleEndian.Uint16(attrs[0:2]))
		attrType := binary.LittleEndian.Uint16(attrs[2:4])
		if attrLen < 4 {
			break
		}
		if attrType == unix.RTA_GATEWAY && attrLen >= 8 {
			gw := make(net.IP, 4)
			copy(gw, attrs[4:attrLen])
			return gw, nil
		}
		aligned := (attrLen + 3) &^ 3
		if aligned > len(attrs) {
			break
		}
		attrs = attrs[aligned:]
	}
	return nil, nil // direct link route — no gateway
}

// AddBypassRoute adds a /32 host route for serverIP via gw so that the VPN
// server's traffic is never routed through the TUN after redirect-gateway is
// applied.  A gateway of nil is accepted (direct link) but the route is only
// useful when a gateway is present.  EEXIST is treated as success.
func AddBypassRoute(serverIP, gw net.IP) error {
	if gw == nil {
		return nil // direct link — no bypass route needed
	}
	err := netlinkRouteMsg(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
		0, serverIP, net.CIDRMask(32, 32), gw)
	if errors.Is(err, syscall.EEXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("routing: add bypass route for %s: %w", serverIP, err)
	}
	return nil
}

// DeleteBypassRoute removes the /32 bypass route added by AddBypassRoute.
// ESRCH (no such route) is treated as success.
func DeleteBypassRoute(serverIP, gw net.IP) error {
	if gw == nil {
		return nil
	}
	err := netlinkRouteMsg(unix.RTM_DELROUTE, 0,
		0, serverIP, net.CIDRMask(32, 32), gw)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("routing: delete bypass route for %s: %w", serverIP, err)
	}
	return nil
}

// addRoute6 adds an IPv6 route via RTM_NEWROUTE.
func addRoute6(ifIndex int, dst net.IP, prefixLen int, gw net.IP) error {
	return netlinkRouteMsg6(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
		ifIndex, dst, prefixLen, gw)
}

// delRoute6 removes an IPv6 route via RTM_DELROUTE.
func delRoute6(ifIndex int, dst net.IP, prefixLen int, gw net.IP) error {
	return netlinkRouteMsg6(unix.RTM_DELROUTE, 0, ifIndex, dst, prefixLen, gw)
}

// nlAttr serialises a single rtattr: 2-byte length + 2-byte type + data.
func nlAttr(typ uint16, data []byte) []byte {
	attrLen := 4 + len(data)
	b := make([]byte, attrLen)
	binary.LittleEndian.PutUint16(b[0:2], uint16(attrLen))
	binary.LittleEndian.PutUint16(b[2:4], typ)
	copy(b[4:], data)
	// Pad to 4-byte boundary.
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// marshalNlHdr serialises a unix.NlMsghdr to wire format (16 bytes).
func marshalNlHdr(h unix.NlMsghdr) []byte {
	b := make([]byte, nlmsgHdrSize)
	binary.LittleEndian.PutUint32(b[0:4], h.Len)
	binary.LittleEndian.PutUint16(b[4:6], h.Type)
	binary.LittleEndian.PutUint16(b[6:8], h.Flags)
	binary.LittleEndian.PutUint32(b[8:12], h.Seq)
	binary.LittleEndian.PutUint32(b[12:16], h.Pid)
	return b
}

// marshalRtMsg serialises a unix.RtMsg to wire format (12 bytes).
func marshalRtMsg(m unix.RtMsg) []byte {
	return []byte{
		m.Family,
		m.Dst_len,
		m.Src_len,
		m.Tos,
		m.Table,
		m.Protocol,
		byte(m.Scope),
		m.Type,
		byte(m.Flags), byte(m.Flags >> 8), byte(m.Flags >> 16), byte(m.Flags >> 24),
	}
}

// parseNlError reads a netlink NLMSG_ERROR response and returns an error if
// the kernel reported a failure.
func parseNlError(buf []byte) error {
	if len(buf) < nlmsgHdrSize {
		return fmt.Errorf("netlink: response too short (%d bytes)", len(buf))
	}
	msgType := binary.LittleEndian.Uint16(buf[4:6])
	if msgType != unix.NLMSG_ERROR {
		// NLMSG_DONE or other — treat as success.
		return nil
	}
	if len(buf) < nlmsgHdrSize+4 {
		return fmt.Errorf("netlink: NLMSG_ERROR too short")
	}
	// The error code is a signed int32 immediately after the nlmsghdr, in
	// native (little-endian) byte order. A value of 0 means success.
	errCode := int32(binary.LittleEndian.Uint32(buf[nlmsgHdrSize:]))
	if errCode == 0 {
		return nil
	}
	return fmt.Errorf("netlink: %w", syscall.Errno(-errCode))
}

// AddIPv6Addr assigns an IPv6 address with the given prefix length to the
// interface identified by ifIndex.  It uses RTM_NEWADDR via the netlink
// socket — the SIOCS* ioctls only work for AF_INET.
//
// This is equivalent to: ip -6 addr add <local>/<prefix> dev <iface>
//
// Requires CAP_NET_ADMIN.
func AddIPv6Addr(ifIndex int, local net.IP, prefix int) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(sock)

	lsa := unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(sock, &lsa); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	ifaMsg := ifAddrMsg{
		Family:    unix.AF_INET6,
		Prefixlen: uint8(prefix),
		Flags:     0,
		Scope:     unix.RT_SCOPE_UNIVERSE,
		Index:     uint32(ifIndex),
	}

	local16 := local.To16()
	rtaAddr := nlAttr(unix.IFA_ADDRESS, local16)
	rtaLocal := nlAttr(unix.IFA_LOCAL, local16)

	payload := marshalIfAddrMsg(ifaMsg)
	payload = append(payload, rtaAddr...)
	payload = append(payload, rtaLocal...)

	return sendNetlinkMsg(sock, unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, payload)
}

// ifAddrMsg is the wire layout of struct ifaddrmsg (linux/if_addr.h, 8 bytes).
type ifAddrMsg struct {
	Family    uint8
	Prefixlen uint8
	Flags     uint8
	Scope     uint8
	Index     uint32
}

func marshalIfAddrMsg(m ifAddrMsg) []byte {
	b := make([]byte, 8)
	b[0] = m.Family
	b[1] = m.Prefixlen
	b[2] = m.Flags
	b[3] = byte(m.Scope)
	binary.LittleEndian.PutUint32(b[4:8], m.Index)
	return b
}

// InterfaceIndex returns the kernel interface index for the named interface.
// This is a convenience wrapper around net.InterfaceByName so callers do not
// need to import "net" just for a single lookup.
func InterfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("routing: interface %q: %w", name, err)
	}
	return iface.Index, nil
}
