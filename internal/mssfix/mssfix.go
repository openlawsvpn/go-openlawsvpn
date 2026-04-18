// Package mssfix clamps the TCP MSS option in SYN and SYN-ACK packets.
//
// This is the software equivalent of the kernel xt_tcpmss / TCPMSS target.
// It is applied to plaintext IPv4/IPv6 packets in the TUN data path so that
// TCP connections negotiated through the tunnel respect the tunnel MTU.
//
// Reference: openvpn3-core tun/builder/capture.hpp MSSPayload::mssfix_ipv4/ipv6
package mssfix

import (
	"encoding/binary"
)

// Clamp rewrites the TCP MSS option in pkt if pkt is a TCP SYN or SYN-ACK
// carrying an MSS option larger than maxMSS.  The IP and TCP checksums are
// updated in-place.  pkt is modified directly; no allocation occurs.
//
// maxMSS is typically MTU - 40 (IPv4) or MTU - 60 (IPv6) to leave room for
// IP + TCP headers.  Passing maxMSS ≤ 0 is a no-op.
func Clamp(pkt []byte, maxMSS int) {
	if maxMSS <= 0 || len(pkt) < 20 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		clamp4(pkt, maxMSS)
	case 6:
		clamp6(pkt, maxMSS)
	}
}

func clamp4(pkt []byte, maxMSS int) {
	if len(pkt) < 20 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return
	}
	if pkt[9] != 6 { // not TCP
		return
	}
	tcp := pkt[ihl:]
	if !clampTCP(tcp, maxMSS) {
		return
	}
	// Recalculate IP checksum (header only, no pseudo-header for IPv4 header).
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:ihl]))
	// Recalculate TCP checksum over pseudo-header + TCP segment.
	fixTCPChecksum4(pkt, ihl)
}

func clamp6(pkt []byte, maxMSS int) {
	if len(pkt) < 40 {
		return
	}
	if pkt[6] != 6 { // next header must be TCP (no extension header support)
		return
	}
	tcp := pkt[40:]
	if !clampTCP(tcp, maxMSS) {
		return
	}
	fixTCPChecksum6(pkt)
}

// clampTCP rewrites the MSS TCP option in a TCP segment if it exceeds maxMSS.
// Returns true if the checksum needs updating.
func clampTCP(tcp []byte, maxMSS int) bool {
	if len(tcp) < 20 {
		return false
	}
	flags := tcp[13]
	syn := flags&0x02 != 0
	if !syn {
		return false
	}
	dataOffset := int(tcp[12]>>4) * 4
	if dataOffset < 20 || len(tcp) < dataOffset {
		return false
	}
	opts := tcp[20:dataOffset]
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 { // end of options
			break
		}
		if kind == 1 { // NOP
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		length := int(opts[i+1])
		if length < 2 || i+length > len(opts) {
			break
		}
		if kind == 2 && length == 4 { // MSS option
			cur := int(binary.BigEndian.Uint16(opts[i+2:]))
			if cur > maxMSS {
				binary.BigEndian.PutUint16(opts[i+2:], uint16(maxMSS))
				return true
			}
			return false
		}
		i += length
	}
	return false
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func fixTCPChecksum4(pkt []byte, ihl int) {
	tcp := pkt[ihl:]
	tcpLen := len(pkt) - ihl
	// pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + tcpLen(2)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], pkt[12:16])
	copy(pseudo[4:8], pkt[16:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(tcpLen))
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], checksumVec(pseudo, tcp))
}

func fixTCPChecksum6(pkt []byte) {
	tcp := pkt[40:]
	tcpLen := len(tcp)
	// IPv6 pseudo-header: src(16) + dst(16) + tcpLen(4) + zeros(3) + nexthdr(1)
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], pkt[8:24])
	copy(pseudo[16:32], pkt[24:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(tcpLen))
	pseudo[39] = 6
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], checksumVec(pseudo, tcp))
}

func checksumVec(a, b []byte) uint16 {
	var sum uint32
	addBytes := func(buf []byte) {
		for i := 0; i+1 < len(buf); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(buf[i:]))
		}
		if len(buf)%2 != 0 {
			sum += uint32(buf[len(buf)-1]) << 8
		}
	}
	addBytes(a)
	addBytes(b)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
